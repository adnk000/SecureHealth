from flask import Flask, render_template, request, session, redirect, make_response
import sqlite3
import csv
import io
from datetime import datetime

# Importing from our modular files
from security import hash_password, can_user_read, mask_name
from database import init_db

app = Flask(__name__)
app.secret_key = "secret_security_key"

def get_db_connection():
    conn = sqlite3.connect('hospital.db')
    conn.row_factory = sqlite3.Row # This lets us use column names like dictionaries
    return conn

@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/login')
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM records')
    all_records = cursor.fetchall()
    
    accessible_records = []
    for r in all_records:
        if can_user_read(session['clearance'], r['security_label']):
            record_dict = dict(r)
            if session['clearance'] == 1:
                record_dict['patient_name'] = mask_name(record_dict['patient_name'])
            accessible_records.append(record_dict)
            
    security_alerts = []
    if session['clearance'] == 3: # Only Level 3 (Doctor/Admin) sees IDS alerts
        cursor.execute('SELECT * FROM security_logs ORDER BY attempt_time DESC')
        security_alerts = cursor.fetchall()
        
    conn.close()
    return render_template('dashboard.html', records=accessible_records, alerts=security_alerts)

@app.route('/presentation')
def presentation():
    return render_template('presentation.html')

@app.route('/patient/<int:patient_id>')
def patient_detail(patient_id):
    if 'username' not in session:
        return redirect('/login')
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM records WHERE id = ?', (patient_id,))
    record = cursor.fetchone()
    conn.close()
    
    # Enforce Bell-LaPadula on the detail page
    if record and can_user_read(session['clearance'], record['security_label']):
        record_dict = dict(record)
        if session['clearance'] == 1:
            record_dict['patient_name'] = mask_name(record_dict['patient_name'])
        return render_template('detail.html', record=record_dict)
    else:
        return "Security Violation: Access Denied by Bell-LaPadula Model", 403

@app.route('/patient/<int:patient_id>/edit', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if 'username' not in session:
        return redirect('/login')
        
    # Enforce Write Access Control: Only Level 3 Doctors can edit
    if session.get('clearance') != 3:
        return "Security Violation: Write-Access Denied. Only Clearance Level 3 can edit records.", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        new_diagnosis = request.form['diagnosis']
        new_medicines = request.form['medicines']
        
        # Update the database
        cursor.execute('UPDATE records SET diagnosis = ?, prescribed_medicines = ? WHERE id = ?', 
                       (new_diagnosis, new_medicines, patient_id))
        
        # AUDITING: Log that the doctor made a change
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO security_logs VALUES (?, ?, ?)", 
                       (session['username'], timestamp, f"UPDATED_RECORD_ID_{patient_id}"))
        
        conn.commit()
        conn.close()
        return redirect(f'/patient/{patient_id}')

    # For GET request, fetch current data to pre-fill the form
    cursor.execute('SELECT * FROM records WHERE id = ?', (patient_id,))
    record = cursor.fetchone()
    conn.close()
    return render_template('edit.html', record=record)

# --- THE HIGHLIGHT FEATURE: BREAK-GLASS PROTOCOL ---
@app.route('/emergency_override')
def emergency_override():
    if 'username' in session and session['clearance'] < 3:
        # 1. Log the severe security exception immediately
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO security_logs VALUES (?, ?, ?)", 
                       (session['username'], timestamp, "CRITICAL: BREAK-GLASS PROTOCOL ACTIVATED"))
        conn.commit()
        conn.close()
        
        # 2. Temporarily elevate clearance to Level 3 for this session
        session['clearance'] = 3 
        session['emergency_mode'] = True
        
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = hash_password(request.form['password'])
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT clearance_level FROM users WHERE username=? AND password=?", (user, pwd))
        result = cursor.fetchone()
        
        if result:
            session['username'] = user
            session['clearance'] = result['clearance_level']
            conn.close()
            return redirect('/')
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO security_logs VALUES (?, ?, ?)", (user, timestamp, "FAILED_LOGIN_ATTEMPT"))
            conn.commit()
            conn.close()
            return render_template('login.html', error="Invalid Login! Attempt logged.")
            
    return render_template('login.html', error=None)

@app.route('/download_audit')
def download_audit():
    if session.get('clearance') != 3: 
        return "Access Denied: Insufficient Clearance", 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_logs ORDER BY attempt_time DESC')
    logs = cursor.fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Attempted Username', 'Timestamp', 'Event Type'])
    cw.writerows(logs)

    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=IDS_Audit_Report.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


    