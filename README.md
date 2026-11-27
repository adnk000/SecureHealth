# SecureHealth — Secure Medical Records Management System

SecureHealth is an educational Flask and SQLite application that demonstrates role-based access to synthetic medical records, information-flow controls inspired by the Bell-LaPadula model, patient-name masking, dashboard analytics, and security audit monitoring.

> **Academic prototype only:** This project uses synthetic demonstration records. It is not a certified medical-record system and must not be used to store real patient information or deployed as-is in a clinical environment.

## Features

### Access control and privacy
- Three clearance levels: Intern (1), Nurse (2), Doctor (3).
- Server-side record filtering using the Bell-LaPadula **No Read Up** rule.
- Patient-name masking for Level 1 users.
- Record editing restricted to Level 3 users.
- Emergency-access requests are logged for review; they do **not** elevate the requester's clearance.

### Dashboard and patient records
- Role-aware dashboard statistics calculated from records accessible to the signed-in user.
- Patient search across the visible patient-record rows, including patient name and diagnosis.
- Classification filter limited to levels the current user is allowed to access.
- Combined search and classification filtering, results count, no-results message, and clear-filters control.

### Security monitoring
- Password hashing with Werkzeug's scrypt-based password hashing.
- One-time migration of existing legacy SHA-256 password hashes after a successful login.
- CSRF token validation for state-changing POST requests.
- Login-success, login-failure, record-update, and emergency-request audit events.
- Audit-log viewing restricted to Level 3.
- Doctor audit filters for username and event category: successful logins, failed logins, record updates, and emergency requests.
- Audit dashboard displays up to the latest 200 matching events and reports the matching count against the total number of recorded events.
- Audit CSV export restricted to Level 3.
- HttpOnly and SameSite session cookies, configurable Secure cookies, and basic security response headers.

## Technology

- Python 3
- Flask
- SQLite
- Werkzeug
- Jinja2
- HTML, Tailwind CSS (CDN), and browser-side JavaScript

## Run locally

### 1. Clone and enter the project

```bash
git clone https://github.com/adnk000/SecureHealth.git
cd SecureHealth
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Configure the application secret

For local development, the application creates a random `.secret_key` file automatically if `SECRET_KEY` is not set. This file is excluded from Git.

For deployment, set a strong `SECRET_KEY` environment variable. Windows PowerShell:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Linux/macOS:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

When serving over HTTPS, also set `COOKIE_SECURE=1`. Leave it unset for local HTTP testing. Do not use Flask's development server in production.

### 5. Start the application

```powershell
python app.py
```

Open http://127.0.0.1:5000. On first launch, the application creates `hospital.db` with synthetic sample records and demo accounts. The database is local and excluded from Git. Existing local records are retained.

## Demo accounts

| Role | Username | Demo password | Clearance |
|---|---|---|---:|
| Intern | `intern_joe` | `password123` | 1 |
| Nurse | `nurse_jackie` | `nurse123` | 2 |
| Doctor | `dr_smith` | `admin456` | 3 |

These credentials are for local demonstration only. Change or remove them before any shared deployment. The login page does not display passwords.

## Access-control model

| User clearance | Records visible | Edit records | View/export audit log |
|---:|---|---|---|
| 1 — Intern | Labels 1 | No | No |
| 2 — Nurse | Labels 1 and 2 | No | No |
| 3 — Doctor | Labels 1, 2 and 3 | Yes | Yes |

The read rule is `user_clearance >= record_security_label`. A user cannot read a record above their clearance. Level 1 users receive masked patient names. The prototype restricts record editing to Level 3; it should not be described as a complete implementation of every Bell-LaPadula property.

Dashboard statistics are derived from the records already authorized for the current user. Patient search and classification filters operate on those authorized records; they do not grant additional access.

## Security behaviour to demonstrate

1. Sign in as the Intern. Only Level 1 records should appear, patient names should be masked, and the dashboard counts should reflect accessible records.
2. Use patient search to find a name or diagnosis. Combine it with the classification filter and use Clear to reset both controls.
3. Sign in as the Nurse. Level 1 and Level 2 records should be accessible, but Level 3 records should remain restricted.
4. Sign in as the Doctor. All records should be readable and editable. Show dashboard analytics.
5. As Doctor, filter audit events by username and event category. The dashboard shows up to the latest 200 matching events.
6. Download the audit CSV as Doctor.
7. Edit a record as the Doctor. The update should appear in the audit log.
8. Submit an emergency-access request as a lower-clearance user. The request is logged, but the user's clearance remains unchanged.
9. Submit an invalid login, then sign in as Doctor and show the failed-login event in the audit dashboard.
10. Attempt to open a Level 3 patient record as Intern and show the HTTP 403 response.
11. Submit a POST request without a valid CSRF token. The application should reject it with HTTP 400.
12. Log in to an existing account. Its legacy SHA-256 password hash is upgraded to a salted scrypt hash after successful authentication.

## Automated tests

Run all tests from the project root with the virtual environment activated:

```powershell
python -m unittest discover -s tests -v
```

The test suite currently contains **15 tests**:
- 7 security helper tests covering password hashing and verification, legacy hash migration, Bell-LaPadula read checks, invalid clearance values, and patient-name masking.
- 8 Flask route tests covering anonymous access, clearance-based dashboards and patient access, audit CSV authorization/export, and CSRF rejection.

The route tests use a temporary SQLite database so they do not modify the local demonstration database.

## Screenshots

The `screenshots/` directory contains captured application screenshots for the login page, Intern/Nurse/Doctor dashboards, patient details, record editing, access denial, and audit CSV report.

## Project structure

```text
SecureHealth/
├── app.py
├── database.py
├── security.py
├── requirements.txt
├── README.md
├── screenshots/
│   ├── 01-login.png
│   ├── 02-intern-dashboard.png
│   ├── 03-nurse-dashboard.png
│   ├── 04-doctor-dashboard.png
│   ├── 05-patient-details.png
│   ├── 06-edit-record.png
│   ├── 07-access-denied.png
│   └── 08-audit-report.png
├── templates/
│   ├── dashboard.html
│   ├── detail.html
│   ├── edit.html
│   ├── login.html
│   └── presentation.html
└── tests/
    ├── test_security.py
    └── test_routes.py
```

## Limitations and future work

- Add independently approved, time-limited emergency access with automatic expiry.
- Add rate limiting and account lockout for repeated failed logins.
- Add database backups, encryption at rest, and a production WSGI server.
- Add stronger audit-log integrity controls and privacy-preserving reporting.
- Add broader route and workflow tests, including login, record editing, emergency requests, and audit-filter combinations.
- Complete independent security testing and applicable legal/compliance review before real-world use.

