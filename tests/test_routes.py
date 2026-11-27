import csv
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as securehealth_app
from security import hash_password


class RouteSecurityTests(unittest.TestCase):
    """Integration tests for Flask routes using an isolated temporary database."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test_hospital.db"
        self.original_database_path = securehealth_app.DATABASE_PATH
        securehealth_app.DATABASE_PATH = self.database_path

        conn = sqlite3.connect(self.database_path)
        conn.executescript(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                clearance_level INTEGER NOT NULL
            );
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_name TEXT,
                gender TEXT,
                blood_group TEXT,
                diagnosis TEXT,
                medical_history TEXT,
                prescribed_medicines TEXT,
                security_label INTEGER
            );
            CREATE TABLE security_logs (
                attempted_user TEXT,
                attempt_time TEXT,
                event_type TEXT
            );
            """
        )
        conn.executemany(
            "INSERT INTO users (username, password, clearance_level) VALUES (?, ?, ?)",
            [
                ("intern_joe", hash_password("password123"), 1),
                ("nurse_jackie", hash_password("nurse123"), 2),
                ("dr_smith", hash_password("admin456"), 3),
            ],
        )
        conn.executemany(
            """INSERT INTO records
               (patient_name, gender, blood_group, diagnosis, medical_history,
                prescribed_medicines, security_label)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                ("Alice LevelOne", "Female", "A+", "Common Flu", "Test history", "Rest", 1),
                ("Bob LevelTwo", "Male", "B+", "Hypertension", "Test history", "Medicine", 2),
                ("Carol LevelThree", "Female", "O+", "Major Trauma", "Test history", "Medicine", 3),
            ],
        )
        conn.executemany(
            "INSERT INTO security_logs (attempted_user, attempt_time, event_type) VALUES (?, ?, ?)",
            [
                ("intern_joe", "2026-01-01 10:00:00 UTC", "SUCCESSFUL_LOGIN"),
                ("unknown", "2026-01-01 10:01:00 UTC", "FAILED_LOGIN_ATTEMPT"),
                ("dr_smith", "2026-01-01 10:02:00 UTC", "UPDATED_RECORD_ID_1"),
            ],
        )
        conn.commit()
        conn.close()

        securehealth_app.app.config.update(TESTING=True, SECRET_KEY="route-test-secret")
        self.client = securehealth_app.app.test_client()

    def tearDown(self):
        securehealth_app.DATABASE_PATH = self.original_database_path
        self.temp_dir.cleanup()

    def login_as(self, username, clearance):
        with self.client.session_transaction() as session:
            session["username"] = username
            session["clearance"] = clearance
            session["csrf_token"] = "test-csrf-token"

    def test_home_redirects_anonymous_user_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_intern_dashboard_only_contains_level_one_records(self):
        self.login_as("intern_joe", 1)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Accessible Records", response.data)
        self.assertIn(b"A**** L****", response.data)
        self.assertNotIn(b"Bob LevelTwo", response.data)
        self.assertNotIn(b"Carol LevelThree", response.data)

    def test_intern_cannot_open_level_three_patient(self):
        self.login_as("intern_joe", 1)
        response = self.client.get("/patient/3")
        self.assertEqual(response.status_code, 403)

    def test_nurse_can_read_level_two_but_not_level_three(self):
        self.login_as("nurse_jackie", 2)
        self.assertEqual(self.client.get("/patient/2").status_code, 200)
        self.assertEqual(self.client.get("/patient/3").status_code, 403)

    def test_doctor_can_open_all_classification_levels(self):
        self.login_as("dr_smith", 3)
        for patient_id in (1, 2, 3):
            with self.subTest(patient_id=patient_id):
                self.assertEqual(
                    self.client.get(f"/patient/{patient_id}").status_code, 200
                )

    def test_non_doctor_cannot_download_audit_csv(self):
        self.login_as("intern_joe", 1)
        self.assertEqual(self.client.get("/download_audit").status_code, 403)

    def test_doctor_can_download_audit_csv(self):
        self.login_as("dr_smith", 3)
        response = self.client.get("/download_audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["Content-Type"])
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(rows[0], ["Attempted Username", "Timestamp", "Event Type"])
        self.assertEqual(len(rows), 4)

    def test_post_without_csrf_token_is_rejected(self):
        self.login_as("dr_smith", 3)
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
