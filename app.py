import csv
import hmac
import io
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, make_response, redirect, render_template, request, session, url_for

from database import init_db
from security import can_user_read, hash_password, mask_name, verify_password

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "hospital.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY is not set. Set it in your environment before starting SecureHealth."
    )

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def utc_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def log_event(username, event):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO security_logs (attempted_user, attempt_time, event_type) VALUES (?, ?, ?)",
        (username, utc_timestamp(), event),
    )
    conn.commit()
    conn.close()

@app.before_request
def protect_post_requests():
    # Create a per-session CSRF token and validate every state-changing POST.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="Invalid or missing CSRF token.")

@app.context_processor
def inject_csrf_token():
    return {"csrf_token": session.get("csrf_token", "")}

@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    all_records = conn.execute("SELECT * FROM records").fetchall()
    alerts = []
    if session.get("clearance") == 3:
        alerts = conn.execute(
            "SELECT * FROM security_logs ORDER BY attempt_time DESC"
        ).fetchall()
    conn.close()

    accessible_records = []
    for record in all_records:
        if can_user_read(session.get("clearance"), record["security_label"]):
            item = dict(record)
            if session.get("clearance") == 1:
                item["patient_name"] = mask_name(item["patient_name"])
            accessible_records.append(item)

    return render_template(
        "dashboard.html", records=accessible_records, alerts=alerts
    )

@app.route("/presentation")
def presentation():
    return render_template("presentation.html")

@app.route("/patient/<int:patient_id>")
def patient_detail(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    record = conn.execute(
        "SELECT * FROM records WHERE id = ?", (patient_id,)
    ).fetchone()
    conn.close()

    if not record or not can_user_read(
        session.get("clearance"), record["security_label"]
    ):
        abort(403, description="Access denied by the Bell-LaPadula policy.")

    item = dict(record)
    if session.get("clearance") == 1:
        item["patient_name"] = mask_name(item["patient_name"])
    return render_template("detail.html", record=item)

@app.route("/patient/<int:patient_id>/edit", methods=["GET", "POST"])
def edit_patient(patient_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("clearance") != 3:
        abort(403, description="Only Level 3 users can edit medical records.")

    conn = get_db_connection()
    record = conn.execute(
        "SELECT * FROM records WHERE id = ?", (patient_id,)
    ).fetchone()

    if not record:
        conn.close()
        abort(404)

    if request.method == "POST":
        diagnosis = request.form.get("diagnosis", "").strip()
        medicines = request.form.get("medicines", "").strip()
        if not diagnosis or not medicines:
            conn.close()
            return render_template(
                "edit.html", record=record, error="Both fields are required."
            ), 400

        conn.execute(
            "UPDATE records SET diagnosis = ?, prescribed_medicines = ? WHERE id = ?",
            (diagnosis, medicines, patient_id),
        )
        conn.execute(
            "INSERT INTO security_logs (attempted_user, attempt_time, event_type) VALUES (?, ?, ?)",
            (session["username"], utc_timestamp(), f"UPDATED_RECORD_ID_{patient_id}"),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("patient_detail", patient_id=patient_id))

    conn.close()
    return render_template("edit.html", record=record)

@app.route("/emergency_override", methods=["POST"])
def emergency_override():
    if "username" not in session:
        return redirect(url_for("login"))

    # A user cannot grant themselves a higher clearance level.
    log_event(session["username"], "EMERGENCY_ACCESS_REQUESTED - approval required")
    return redirect(url_for("home"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        row = conn.execute(
            "SELECT password, clearance_level FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        valid = False
        needs_upgrade = False
        if row:
            valid, needs_upgrade = verify_password(row["password"], password)

        if valid:
            if needs_upgrade:
                conn.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (hash_password(password), username),
                )
                conn.commit()
            conn.close()

            session.clear()
            session["username"] = username
            session["clearance"] = int(row["clearance_level"])
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            log_event(username, "SUCCESSFUL_LOGIN")
            return redirect(url_for("home"))

        conn.close()
        log_event(username or "unknown", "FAILED_LOGIN_ATTEMPT")
        return render_template("login.html", error="Invalid login credentials."), 401

    return render_template("login.html", error=None)

@app.route("/download_audit")
def download_audit():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("clearance") != 3:
        abort(403, description="Only Level 3 users can download audit logs.")

    conn = get_db_connection()
    logs = conn.execute(
        "SELECT * FROM security_logs ORDER BY attempt_time DESC"
    ).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Attempted Username", "Timestamp", "Event Type"])
    writer.writerows([tuple(row) for row in logs])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=SecureHealth_Audit_Report.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

if __name__ == "__main__":
    init_db()
    app.run(debug=False)
