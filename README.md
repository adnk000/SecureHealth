# SecureHealth — Secure Medical Records Management System

SecureHealth is an educational Flask and SQLite application that demonstrates role-based access to synthetic medical records, information-flow controls inspired by the Bell-LaPadula model, patient-name masking, and security audit logging.

> **Academic prototype only:** This project uses synthetic demonstration records. It is not a certified medical-record system and must not be used to store real patient information or deployed as-is in a clinical environment.

## Features

- Three clearance levels: Intern (1), Nurse (2), Doctor (3).
- Server-side record filtering using the Bell-LaPadula **No Read Up** rule.
- Patient-name masking for Level 1 users.
- Record editing restricted to Level 3 users.
- Password hashing with Werkzeug's scrypt-based password hashing.
- One-time migration of existing legacy SHA-256 password hashes after a successful login.
- CSRF token validation for state-changing POST requests.
- Login-success, login-failure, record-update, and emergency-request audit events.
- Audit-log viewing and CSV export restricted to Level 3.
- Emergency-access requests are logged for review; they do **not** elevate the requester's clearance.
- HttpOnly and SameSite session cookies, configurable Secure cookies, and basic security response headers.

## Technology

- Python 3, Flask, SQLite, Werkzeug, Jinja2, HTML, Tailwind CSS (CDN).

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
pip install -r requirements.txt
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
py app.py
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

## Security behaviour to demonstrate

1. Sign in as the Intern. Only Level 1 records should appear and names should be masked.
2. Sign in as the Nurse. Level 1 and Level 2 records should be accessible, but Level 3 records should remain restricted.
3. Sign in as the Doctor. All records should be readable and editable.
4. Edit a record as the Doctor. The update should appear in the audit log.
5. Submit an emergency-access request as a lower-clearance user. The request is logged, but the user's clearance remains unchanged.
6. Submit an invalid login, then sign in as Doctor and show the failed-login event in the audit dashboard.
7. Submit a POST request without a valid CSRF token. The application should reject it with HTTP 400.
8. Log in to an existing account. Its legacy SHA-256 password hash is upgraded to a salted scrypt hash after successful authentication.

## Tests

Run the security helper tests:

```powershell
py -m unittest discover -s tests -v
```

## Project structure

```text
SecureHealth/
├── app.py
├── database.py
├── security.py
├── requirements.txt
├── templates/
│   ├── dashboard.html
│   ├── detail.html
│   ├── edit.html
│   ├── login.html
│   └── presentation.html
└── tests/
    └── test_security.py
```

## Limitations and future work

- Add independently approved, time-limited emergency access with automatic expiry.
- Add rate limiting and account lockout for repeated failed logins.
- Add database backups, encryption at rest, and a production WSGI server.
- Add stronger audit-log integrity controls and privacy-preserving reporting.
- Complete independent security testing and applicable legal/compliance review before real-world use.
