import sqlite3
import random
from security import hash_password

def init_db():
    conn = sqlite3.connect('hospital.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, clearance_level INTEGER)')
    
    # NEW: Added prescribed_medicines TEXT
    cursor.execute('''CREATE TABLE IF NOT EXISTS records 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_name TEXT, gender TEXT, 
                       blood_group TEXT, diagnosis TEXT, medical_history TEXT, prescribed_medicines TEXT, security_label INTEGER)''')
    cursor.execute('CREATE TABLE IF NOT EXISTS security_logs (attempted_user TEXT, attempt_time TEXT, event_type TEXT)')
    
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", ('intern_joe', hash_password('password123'), 1))
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", ('nurse_jackie', hash_password('nurse123'), 2))
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", ('dr_smith', hash_password('admin456'), 3))
        
        first_names = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "Adnan", "Amit"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Khan", "Sharma"]
        blood_groups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
        
        # Updated to include Medicine: (Diagnosis, History, Medicine)
        conditions = {
            1: [ 
                ("Common Flu", "Prescribed rest, fluids.", "Paracetamol 500mg"), 
                ("Sprained Ankle", "Ice, compression, elevation.", "Ibuprofen 400mg"), 
                ("Routine Blood Work", "All levels within normal range.", "None Required"), 
                ("Vitamin D Deficiency", "Fatigue and joint pain reported.", "Cholecalciferol 60K IU")
            ],
            2: [ 
                ("Type 2 Diabetes", "A1C levels at 7.8%.", "Metformin 500mg"), 
                ("Hypertension", "Blood pressure 145/90.", "Lisinopril 10mg"), 
                ("Asthma Flare-up", "Administered nebulizer treatment.", "Albuterol Inhaler"), 
                ("Gastric Ulcer", "Stomach pain reported after meals.", "Omeprazole 20mg")
            ],
            3: [ 
                ("Psychiatric Evaluation", "Exhibits signs of severe clinical depression.", "Sertraline 50mg"), 
                ("Oncology Treatment", "Stage 2 carcinoma. Chemo ongoing.", "Ondansetron (for nausea)"), 
                ("Major Trauma", "ICU admission post-RTA. Critical.", "Morphine 10mg IV"), 
                ("Neurological Assessment", "Evaluating early signs of Alzheimer's.", "Donepezil 5mg")
            ]
        }

        records = []
        for _ in range(65):
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            gender = random.choice(["Male", "Female"])
            bg = random.choice(blood_groups)
            sec_level = random.choices([1, 2, 3], weights=[40, 40, 20])[0]
            
            diag_hist_med = random.choice(conditions[sec_level])
            records.append((name, gender, bg, diag_hist_med[0], diag_hist_med[1], diag_hist_med[2], sec_level))
        
        # Insert all 65 records with the new medicine field
        cursor.executemany("INSERT INTO records (patient_name, gender, blood_group, diagnosis, medical_history, prescribed_medicines, security_label) VALUES (?, ?, ?, ?, ?, ?, ?)", records)
    
    conn.commit()
    conn.close()