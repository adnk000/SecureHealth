# SecureHealth

SecureHealth is a Flask and SQLite demonstration application for protecting sample hospital records with multi-level access control. It demonstrates the Bell-LaPadula **No Read Up** rule, role/clearance-based editing, patient-name masking, authentication, and security audit logging.

> **Academic prototype only:** this project uses synthetic demonstration records. It is not a certified medical-record system and must not be used to store real patient information or deployed as-is in a clinical environment.

## Features

- Three clearance levels: Intern (1), Nurse (2), Doctor (3).
- Server-side record filtering using the Bell-LaPadula No Read Up rule.
- Patient-name masking for Level 1 users.
- Record editing restricted to Level 3 users.
- Password hashing with Werkzeug's scrypt-based password hashing.
- One-time migration of existing legacy SHA-256 password hashes after a successful login.
- CSRF token validation for POST requests.
- Login-failure and record-update audit events.
- Audit-log viewing and CSV export restricted to Level 3.
- Emergency-access requests are logged for review; **they do not elevate the requester's clearance**.
- HttpOnly and SameSite session cookies, configurable Secure cookies, and basic security response headers.

## Technology

- Python 3
- Flask
- SQLite
- Werkzeug
- Jinja2, HTML, Tailwind CSS (CDN)

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

### 4. Set a secret key

Windows PowerShell:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Linux/macOS:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Do not commit your real secret key. For HTTPS deployments, also set `COOKIE_SECURE=1`. Leave it unset for local HTTP testing.

### 5. Start the application

```bash
python app.py
```

Open http://127.0.0.1:5000.

The application initializes the SQLite schema and creates sample users/records if the database is empty. Existing database records are retained.

## Demo accounts

| Role | Username | Demo password | Clearance |
|---|---|---|---:|
| Intern | `intern_joe` | `password123` | 1 |
| Nurse | `nurse_jackie` | `nurse123` | 2 |
| Doctor | `dr_smith` | `admin456` | 3 |

These credentials are for local demonstration only. Change or remove them before any shared deployment.

## Access-control model

| User clearance | Records visible | Edit records | View/export audit log |
|---:|---|---|---|
| 1 — Intern | Labels 1 | No | No |
| 2 — Nurse | Labels 1 and 2 | No | No |
| 3 — Doctor | Labels 1, 2 and 3 | Yes | Yes |

The read rule is:

`user_clearance >= record_security_label`

A user cannot read a record above their clearance. Level 1 users receive masked patient names. The prototype restricts record editing to Level 3; it should not be described as a complete implementation of every Bell-LaPadula property.

## Security notes

- Passwords are stored as Werkzeug password hashes, not plaintext.
- Existing SHA-256 hashes are upgraded to the current hash format after a successful login.
- The application refuses to start if `SECRET_KEY` is missing.
- All state-changing POST forms require a CSRF token.
- Emergency access is a logged request only. It does not grant privileges automatically.
- The built-in Flask development server is for local demonstration, not production hosting.

## Run the security helper tests

After installing dependencies, run:

```bash
python -m unittest discover -s tests -v
```

These tests cover password hashing and legacy-hash migration, invalid passwords, Bell-LaPadula read checks, and name masking.

## Suggested demonstration

1. Sign in as the Intern and show that Level 3 records are inaccessible and names are masked.
2. Sign in as the Nurse and show access to Level 1 and Level 2 records only.
3. Sign in as the Doctor and demonstrate full record visibility and an audited record edit.
4. Submit an emergency-access request as a lower-clearance user; verify that the request is logged but the clearance remains unchanged.
5. Attempt an invalid login, then sign in as Doctor and show the failed-login event in the audit dashboard.
6. Export the audit log as CSV.

## Project structure

```text
SecureHealth/
├── app.py
├── database.py
├── security.py
├── hospital.db
├── requirements.txt
└── templates/
    ├── dashboard.html
    ├── detail.html
    ├── edit.html
    ├── login.html
    └── presentation.html
```

## Limitations and future work

- Add automated integration tests for every role and route.
- Add administrator-managed, independently approved emergency access with automatic expiry.
- Add rate limiting and account lockout for repeated failed logins.
- Add database backups, encryption at rest, and a production WSGI server.
- Add stronger audit-log integrity controls and privacy-preserving reporting.
