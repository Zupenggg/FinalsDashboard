
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "data", "templates"),
    static_folder=os.path.join(BASE_DIR, "data", "templates", "static")
)

DATA_FOLDER = os.path.join(BASE_DIR, "data")
DATA_FILE = os.environ.get(
    "DATA_FILE",
    os.path.join(DATA_FOLDER, "data.json"),
)
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

os.makedirs(DATA_FOLDER, exist_ok=True)


def load_secret_key():
    configured_key = os.environ.get("FLASK_SECRET_KEY")
    if configured_key:
        return configured_key

    secret_file = os.path.join(DATA_FOLDER, ".flask_secret")
    try:
        with open(secret_file, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        secret_key = secrets.token_hex(32)
        try:
            with open(secret_file, "x", encoding="utf-8") as file:
                file.write(secret_key)
            return secret_key
        except FileExistsError:
            with open(secret_file, "r", encoding="utf-8") as file:
                return file.read().strip()


app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true",
)
if os.environ.get("RENDER") == "true":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def initial_data():
    admin_username = os.environ.get("ADMIN_USERNAME", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if not admin_username or len(admin_password) < 12:
        raise RuntimeError(
            "The data store is empty. Set ADMIN_USERNAME and an "
            "ADMIN_PASSWORD of at least 12 characters to initialize it."
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", admin_username):
        raise RuntimeError(
            "ADMIN_USERNAME must be 3-30 letters, numbers, dots, dashes, "
            "or underscores."
        )

    return {
        "students": [],
        "teachers": [],
        "courses": [],
        "attendance": [],
        "notifications": [],
        "settings": {
            "site_name": "School Management System",
            "theme": "light",
        },
        "profile": {
            "name": "Administrator",
            "email": "",
        },
        "users": [{
            "username": admin_username,
            "password": generate_password_hash(admin_password),
            "name": "Administrator",
            "email": "",
            "role": "admin",
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }],
        "login_events": [],
    }


def ensure_database():
    import psycopg
    from psycopg.types.json import Jsonb

    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS dashboard_state (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                payload JSONB NOT NULL
            )
            """
        )
        stored = connection.execute(
            "SELECT payload FROM dashboard_state WHERE id = 1"
        ).fetchone()
        if stored is None:
            connection.execute(
                "INSERT INTO dashboard_state (id, payload) VALUES (1, %s)",
                (Jsonb(initial_data()),),
            )
        else:
            data = stored[0]
            admin = next(
                (user for user in data.get("users", [])
                 if user.get("username", "").casefold() == "admin"),
                None,
            )
            if admin is not None and admin.get("role") != "admin":
                admin["role"] = "admin"
                connection.execute(
                    "UPDATE dashboard_state SET payload = %s WHERE id = 1",
                    (Jsonb(data),),
                )


def ensure_data_file():
    if DATABASE_URL:
        ensure_database()
        return
    if os.path.exists(DATA_FILE):
        return

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    try:
        with open(DATA_FILE, "x", encoding="utf-8") as file:
            json.dump(initial_data(), file, indent=4)
    except FileExistsError:
        return


ensure_data_file()


def load_data():
    if DATABASE_URL:
        import psycopg

        with psycopg.connect(DATABASE_URL) as connection:
            stored = connection.execute(
                "SELECT payload FROM dashboard_state WHERE id = 1"
            ).fetchone()
        if stored is None:
            raise RuntimeError("The dashboard database has not been initialized.")
        return stored[0]
    with open(DATA_FILE, "r") as file:
        return json.load(file)


def save_data(data):
    if DATABASE_URL:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(DATABASE_URL) as connection:
            result = connection.execute(
                """
                UPDATE dashboard_state
                SET payload = %s
                WHERE id = 1
                """,
                (Jsonb(data),),
            )
        if result.rowcount != 1:
            raise RuntimeError("The dashboard database has not been initialized.")
        return
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)


def password_matches(stored_password, submitted_password):
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_password, submitted_password)
    return hmac.compare_digest(stored_password, submitted_password)


def is_admin():
    return session.get("role") == "admin"


def record_login_event(data, username, success):
    events = data.setdefault("login_events", [])
    events.append({
        "username": username or "(blank)",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip_address": request.remote_addr or "unknown",
        "success": success,
    })
    del events[:-1000]


USER_ALLOWED_ENDPOINTS = {
    "limited_access",
    "login",
    "logout",
    "profile",
    "register",
    "static",
    "update_profile",
}


@app.before_request
def require_login():
    if request.endpoint not in ("login", "register", "static") and "username" not in session:
        return redirect(url_for("login"))
    if "username" in session:
        data = load_data()
        current_user = next(
            (user for user in data.get("users", [])
             if user.get("username", "").casefold() == session["username"].casefold()),
            None,
        )
        if current_user is None:
            session.clear()
            return redirect(url_for("login"))
        if current_user.get("username", "").casefold() == "admin":
            role = "admin"
            if current_user.get("role") != role:
                current_user["role"] = role
                save_data(data)
        else:
            role = current_user.get("role", "user")
        if not current_user.get("active", True):
            session.clear()
            return redirect(url_for("login"))
        if role not in ("admin", "user"):
            abort(403)
        if session.get("role") != role:
            session["role"] = role

    if "username" in session and not is_admin():
        if request.endpoint not in USER_ALLOWED_ENDPOINTS:
            if request.method == "POST":
                abort(403)
            return redirect(url_for("limited_access"))
    if request.method == "POST":
        supplied_token = request.form.get("_csrf_token", "")
        session_token = session.get("_csrf_token", "")
        if not session_token or not hmac.compare_digest(supplied_token, session_token):
            abort(400, description="Invalid or missing form security token.")


@app.after_request
def prevent_private_page_caching(response):
    if "username" in session:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.context_processor
def inject_preferences():
    data = load_data()
    settings_data = data.get("settings", {})
    profile_data = data.get("profile", {})
    current_user = next(
        (user for user in data.get("users", [])
         if user.get("username") == session.get("username")),
        {},
    )
    if current_user.get("name"):
        profile_data = {
            "name": current_user["name"],
            "email": current_user.get("email", ""),
        }
    return {
        "site_settings": settings_data,
        "profile_data": profile_data,
        "theme_class": "dark-theme" if settings_data.get("theme") == "dark" else "",
        "is_admin": is_admin(),
        "csrf_token": session.setdefault("_csrf_token", secrets.token_urlsafe(32)),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        data = load_data()
        user = next(
            (item for item in data.get("users", [])
             if item.get("username", "").casefold() == username.casefold()),
            None,
        )
        if user and user.get("active", True) and password_matches(
            str(user.get("password", "")), password
        ):
            if not user["password"].startswith(("scrypt:", "pbkdf2:")):
                user["password"] = generate_password_hash(password)
            user["role"] = (
                "admin" if user.get("username", "").casefold() == "admin"
                else user.get("role", "user")
            )
            record_login_event(data, user["username"], True)
            save_data(data)
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("home"))
        record_login_event(data, username, False)
        save_data(data)
        error = "Invalid username or password."
    return render_template("login.html", error=error), 401 if error else 200


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        data = load_data()

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            error = "Username must be 3–30 characters using letters, numbers, dots, dashes, or underscores."
        elif not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            error = "Enter your name and a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm_password:
            error = "The passwords do not match."
        elif any(
            user.get("username", "").casefold() == username.casefold()
            for user in data.get("users", [])
        ):
            error = "That username is already registered."
        else:
            data.setdefault("users", []).append({
                "username": username,
                "password": generate_password_hash(password),
                "name": name,
                "email": email,
                "role": "user",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
            save_data(data)
            return redirect(url_for("login", registered=1))
    return render_template("register.html", error=error)


@app.route("/")
def home():
    if not is_admin():
        return redirect(url_for("limited_access"))
    data = load_data()
    return render_template("index.html", data=data)


@app.route("/limited-access")
def limited_access():
    if is_admin():
        return redirect(url_for("home"))
    return render_template("limited_access.html", username=session["username"])


def render_section(title, description):
    return render_template(
        "section.html",
        title=title,
        description=description,
    )


RECORD_CONFIG = {
    "teachers": {
        "title": "Teachers",
        "record_label": "Teacher",
        "description": "Add, search, and manage teacher records.",
        "data_key": "teachers",
        "fields": [
            {"name": "id", "label": "Teacher ID", "type": "text"},
            {"name": "name", "label": "Teacher Name", "type": "text"},
            {"name": "subject", "label": "Subject", "type": "text"},
            {"name": "email", "label": "Email", "type": "email"},
        ],
    },
    "courses": {
        "title": "Courses",
        "record_label": "Course",
        "description": "Add, search, and manage courses.",
        "data_key": "courses",
        "fields": [
            {"name": "id", "label": "Course ID", "type": "text"},
            {"name": "name", "label": "Course Name", "type": "text"},
            {"name": "teacher", "label": "Teacher", "type": "text"},
            {"name": "description", "label": "Description", "type": "text"},
        ],
    },
    "attendance": {
        "title": "Attendance",
        "record_label": "Attendance Record",
        "description": "Record and manage student attendance.",
        "data_key": "attendance",
        "fields": [
            {"name": "id", "label": "Record ID", "type": "text"},
            {"name": "student_id", "label": "Student ID", "type": "text"},
            {"name": "student_name", "label": "Student Name", "type": "text"},
            {"name": "course", "label": "Course", "type": "text"},
            {"name": "date", "label": "Date", "type": "date"},
            {
                "name": "status",
                "label": "Status",
                "type": "select",
                "options": ["Present", "Absent", "Late"],
            },
        ],
    },
}


def render_record_manager(resource, error=None, form_record=None, editing=False):
    config = RECORD_CONFIG[resource]
    data = load_data()
    query = request.args.get("q", "").strip()
    records = data.get(config["data_key"], [])
    if query:
        normalized_query = query.casefold()
        fields = [field["name"] for field in config["fields"]]
        records = [
            record for record in records
            if any(
                normalized_query in str(record.get(field, "")).casefold()
                for field in fields
            )
        ]

    return render_template(
        "records.html",
        resource=resource,
        title=config["title"],
        record_label=config["record_label"],
        description=config["description"],
        fields=config["fields"],
        records=records,
        query=query,
        error=error,
        can_manage=is_admin(),
        form_record=form_record or {field["name"]: "" for field in config["fields"]},
        editing=editing,
    )


def handle_records(resource):
    if not is_admin():
        abort(403)
    config = RECORD_CONFIG[resource]
    data = load_data()
    records = data.setdefault(config["data_key"], [])
    action = request.form.get("action", "")
    record_id = request.form.get("id", "").strip()

    if action == "delete":
        updated_records = [
            record for record in records
            if str(record.get("id", "")) != record_id
        ]
        if len(updated_records) == len(records):
            return render_record_manager(resource, "Record not found.")
        data[config["data_key"]] = updated_records
        save_data(data)
        return redirect(url_for(resource))

    new_record = {
        field["name"]: request.form.get(field["name"], "").strip()
        for field in config["fields"]
    }
    if any(not value for value in new_record.values()):
        return render_record_manager(
            resource,
            "Please complete all required fields.",
            new_record,
            editing=action == "update",
        )
    if resource == "attendance" and new_record["status"] not in (
        "Present", "Absent", "Late"
    ):
        return render_record_manager(
            resource,
            "Select a valid attendance status.",
            new_record,
        )

    if action == "add":
        if any(str(record.get("id", "")) == record_id for record in records):
            return render_record_manager(
                resource,
                "A record with that ID already exists.",
                new_record,
            )
        records.append(new_record)
    elif action == "update":
        original_id = request.form.get("original_id", "").strip()
        record = next(
            (item for item in records if str(item.get("id", "")) == original_id),
            None,
        )
        if record is None:
            return render_record_manager(resource, "Record not found.")
        if record_id != original_id and any(
            str(item.get("id", "")) == record_id for item in records
        ):
            return render_record_manager(
                resource,
                "A record with that ID already exists.",
                new_record,
                editing=True,
            )
        record.update(new_record)
    else:
        return render_record_manager(resource, "Invalid record action.")

    save_data(data)
    return redirect(url_for(resource))


def render_students(error=None, form_student=None, editing=False):
    data = load_data()
    query = request.args.get("q", "").strip()
    students_list = data.get("students", [])
    if query:
        normalized_query = query.casefold()
        students_list = [
            student for student in students_list
            if any(
                normalized_query in str(student.get(field, "")).casefold()
                for field in ("id", "name", "course")
            )
        ]

    return render_template(
        "students.html",
        students=students_list,
        query=query,
        error=error,
        can_manage=is_admin(),
        form_student=form_student or {"id": "", "name": "", "course": ""},
        editing=editing,
    )


@app.route('/students', methods=["GET", "POST"])
def students():
    if request.method == "POST" and not is_admin():
        abort(403)
    if request.method == "GET":
        edit_id = request.args.get("edit")
        if edit_id:
            data = load_data()
            student = next(
                (record for record in data.get("students", [])
                 if str(record.get("id", "")) == edit_id),
                None,
            )
            if student is None:
                return render_students("Student record not found.")
            return render_students(form_student=student, editing=True)
        return render_students()

    action = request.form.get("action", "")
    student_id = request.form.get("id", "").strip()
    name = request.form.get("name", "").strip()
    course = request.form.get("course", "").strip()
    data = load_data()
    student_records = data.setdefault("students", [])

    if action == "delete":
        updated_records = [
            student for student in student_records
            if str(student.get("id", "")) != student_id
        ]
        if len(updated_records) == len(student_records):
            return render_students("Student record not found.")
        data["students"] = updated_records
        save_data(data)
        return redirect(url_for("students"))

    if not student_id or not name or not course:
        return render_students(
            "Student ID, name, and course are all required.",
            {"id": student_id, "name": name, "course": course},
            editing=action == "update",
        )

    if action == "add":
        if any(str(student.get("id", "")) == student_id for student in student_records):
            return render_students(
                "A student with that ID already exists.",
                {"id": student_id, "name": name, "course": course},
            )
        student_records.append({"id": student_id, "name": name, "course": course})
    elif action == "update":
        original_id = request.form.get("original_id", "").strip()
        student = next(
            (record for record in student_records
             if str(record.get("id", "")) == original_id),
            None,
        )
        if student is None:
            return render_students("Student record not found.")
        if student_id != original_id and any(
            str(record.get("id", "")) == student_id for record in student_records
        ):
            return render_students(
                "A student with that ID already exists.",
                {"id": student_id, "name": name, "course": course},
                editing=True,
            )
        student.update({"id": student_id, "name": name, "course": course})
    else:
        return render_students("Invalid student action.")

    save_data(data)
    return redirect(url_for("students"))

@app.route('/teachers', methods=["GET", "POST"])
def teachers():
    if request.method == "POST":
        return handle_records("teachers")
    edit_id = request.args.get("edit")
    if edit_id:
        data = load_data()
        record = next(
            (item for item in data.get("teachers", [])
             if str(item.get("id", "")) == edit_id),
            None,
        )
        if record is None:
            return render_record_manager("teachers", "Teacher record not found.")
        return render_record_manager("teachers", form_record=record, editing=True)
    return render_record_manager("teachers")


@app.route('/courses', methods=["GET", "POST"])
def courses():
    if request.method == "POST":
        return handle_records("courses")
    edit_id = request.args.get("edit")
    if edit_id:
        data = load_data()
        record = next(
            (item for item in data.get("courses", [])
             if str(item.get("id", "")) == edit_id),
            None,
        )
        if record is None:
            return render_record_manager("courses", "Course record not found.")
        return render_record_manager("courses", form_record=record, editing=True)
    return render_record_manager("courses")


@app.route('/attendance', methods=["GET", "POST"])
def attendance():
    if request.method == "POST":
        return handle_records("attendance")
    edit_id = request.args.get("edit")
    if edit_id:
        data = load_data()
        record = next(
            (item for item in data.get("attendance", [])
             if str(item.get("id", "")) == edit_id),
            None,
        )
        if record is None:
            return render_record_manager("attendance", "Attendance record not found.")
        return render_record_manager("attendance", form_record=record, editing=True)
    return render_record_manager("attendance")


@app.route('/reports')
def reports():
    data = load_data()
    attendance_records = data.get("attendance", [])
    status_counts = {
        status: sum(
            1 for record in attendance_records
            if record.get("status", "").casefold() == status.casefold()
        )
        for status in ("Present", "Absent", "Late")
    }
    total_attendance = len(attendance_records)
    present_rate = (
        round(status_counts["Present"] * 100 / total_attendance, 1)
        if total_attendance else 0
    )
    return render_template(
        "reports.html",
        students=data.get("students", []),
        teachers=data.get("teachers", []),
        courses=data.get("courses", []),
        attendance=attendance_records,
        status_counts=status_counts,
        present_rate=present_rate,
    )

@app.route('/profile')
def profile(error=None):
    data = load_data()
    user = next(
        (item for item in data.get("users", [])
         if item.get("username") == session["username"]),
        None,
    )
    if user is None:
        abort(401)
    profile_data = {
        "name": user.get("name", data.get("profile", {}).get("name", "Administrator")),
        "email": user.get("email", data.get("profile", {}).get("email", "")),
    }
    return render_template(
        "profile.html",
        profile=profile_data,
        error=error,
        updated=request.args.get("updated") == "1",
        username=session["username"],
    )


@app.route('/profile', methods=["POST"])
def update_profile():
    data = load_data()
    user = next(
        (item for item in data.get("users", [])
         if item.get("username") == session["username"]),
        None,
    )
    if user is None:
        abort(401)
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not name or not email or "@" not in email:
        return profile("Enter a name and a valid email address.")

    if new_password or confirm_password or current_password:
        user = next(
            (item for item in data.get("users", [])
             if item.get("username") == session["username"]),
            None,
        )
        if not user or not password_matches(
            str(user.get("password", "")), current_password
        ):
            return profile("Enter your current password to change it.")
        if len(new_password) < 8:
            return profile("The new password must be at least 8 characters.")
        if new_password != confirm_password:
            return profile("The new passwords do not match.")
        user["password"] = generate_password_hash(new_password)

    user.update({"name": name, "email": email})
    if user.get("role") == "admin":
        data.setdefault("profile", {}).update({"name": name, "email": email})
    save_data(data)
    return redirect(url_for("profile", updated=1))

@app.route('/settings')
def settings():
    if not is_admin():
        abort(403)
    data = load_data()
    settings_data = data.setdefault(
        "settings", {"site_name": "School Management System", "theme": "light"}
    )
    return render_template(
        "settings.html",
        settings=settings_data,
        error=None,
        updated=request.args.get("updated") == "1",
    )


@app.route('/settings', methods=["POST"])
def update_settings():
    if not is_admin():
        abort(403)
    data = load_data()
    settings_data = data.setdefault(
        "settings", {"site_name": "School Management System", "theme": "light"}
    )
    site_name = request.form.get("site_name", "").strip()
    theme = request.form.get("theme", "")
    if not site_name:
        return render_template(
            "settings.html",
            settings=settings_data,
            error="School name is required.",
            updated=False,
        )
    if theme not in ("light", "dark"):
        return render_template(
            "settings.html",
            settings=settings_data,
            error="Select a valid theme.",
            updated=False,
        )
    settings_data.update({"site_name": site_name, "theme": theme})
    save_data(data)
    return redirect(url_for("settings", updated=1))


@app.route("/access")
def access():
    if not is_admin():
        abort(403)
    data = load_data()
    events = list(reversed(data.get("login_events", [])))
    users = data.get("users", [])
    return render_template(
        "access.html",
        users=users,
        events=events[:200],
    )


@app.route("/access/users/<username>", methods=["POST"])
def update_access_user(username):
    if not is_admin():
        abort(403)

    data = load_data()
    user = next(
        (item for item in data.get("users", [])
         if item.get("username", "").casefold() == username.casefold()),
        None,
    )
    if user is None:
        abort(404)
    if user.get("username", "").casefold() == "admin":
        abort(403, description="The primary administrator account cannot be changed here.")

    action = request.form.get("action", "")
    if action == "save":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            abort(400, description="Enter a name and a valid email address.")
        if new_password and len(new_password) < 8:
            abort(400, description="Password must be at least 8 characters.")
        user.update({"name": name, "email": email})
        if new_password:
            user["password"] = generate_password_hash(new_password)
    elif action == "toggle":
        user["active"] = not user.get("active", True)
    else:
        abort(400, description="Invalid user management action.")

    save_data(data)
    return redirect(url_for("access", updated=username))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )