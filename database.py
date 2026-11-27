import os
import random
import sqlite3
from pathlib import Path

from security import hash_password

DATABASE_PATH = Path(__file__).resolve().parent / "hospital.db"
MIN_RECORD_COUNT = 350


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            clearance_level INTEGER NOT NULL CHECK (clearance_level BETWEEN 1 AND 3)
        )"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT,
            gender TEXT,
            blood_group TEXT,
            diagnosis TEXT,
            medical_history TEXT,
            prescribed_medicines TEXT,
            security_label INTEGER
        )"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS security_logs (
            attempted_user TEXT,
            attempt_time TEXT,
            event_type TEXT
        )"""
    )

    # Existing databases are preserved. Demo accounts are created only once.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        demo_users = [
            ("intern_joe", hash_password("password123"), 1),
            ("nurse_jackie", hash_password("nurse123"), 2),
            (
                "dr_smith",
                hash_password(os.environ.get("DEMO_DOCTOR_PASSWORD", "admin456")),
                3,
            ),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, clearance_level) VALUES (?, ?, ?)",
            demo_users,
        )

    first_names = [
        "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
        "Michael", "Linda", "William", "Elizabeth", "Adnan", "Amit",
    ]
    last_names = [
        "Smith", "Johnson", "Williams", "Brown", "Jones",
        "Garcia", "Miller", "Davis", "Khan", "Sharma",
    ]
    blood_groups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
    conditions = {
        1: [
            ("Common Flu", "Prescribed rest, fluids.", "Paracetamol 500mg"),
            ("Sprained Ankle", "Ice, compression, elevation.", "Ibuprofen 400mg"),
            ("Routine Blood Work", "All levels within normal range.", "None Required"),
            ("Vitamin D Deficiency", "Fatigue and joint pain reported.", "Cholecalciferol 60K IU"),
        ],
        2: [
            ("Type 2 Diabetes", "A1C levels at 7.8%.", "Metformin 500mg"),
            ("Hypertension", "Blood pressure 145/90.", "Lisinopril 10mg"),
            ("Asthma Flare-up", "Administered nebulizer treatment.", "Albuterol Inhaler"),
            ("Gastric Ulcer", "Stomach pain reported after meals.", "Omeprazole 20mg"),
        ],
        3: [
            ("Psychiatric Evaluation", "Synthetic demonstration record.", "Sertraline 50mg"),
            ("Oncology Treatment", "Synthetic demonstration record.", "Ondansetron"),
            ("Major Trauma", "Synthetic demonstration record.", "Morphine 10mg IV"),
            ("Neurological Assessment", "Synthetic demonstration record.", "Donepezil 5mg"),
        ],
    }

    # Top up existing databases as well as seeding fresh ones. Checking the
    # current count makes initialization safe to run on every application start.
    cursor.execute("SELECT COUNT(*) FROM records")
    missing_records = max(0, MIN_RECORD_COUNT - cursor.fetchone()[0])
    records = []
    for _ in range(missing_records):
        patient_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        gender = random.choice(["Male", "Female"])
        blood_group = random.choice(blood_groups)
        label = random.choices([1, 2, 3], weights=[40, 40, 20])[0]
        diagnosis, history, medicines = random.choice(conditions[label])
        records.append(
            (patient_name, gender, blood_group, diagnosis, history, medicines, label)
        )

    cursor.executemany(
        """INSERT INTO records
        (patient_name, gender, blood_group, diagnosis, medical_history,
         prescribed_medicines, security_label)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        records,
    )

    conn.commit()
    conn.close()

