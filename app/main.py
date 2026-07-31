import sqlite3
import re
from datetime import datetime
from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="SIEM & Incident Suite")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Configuración e Inicialización de la Base de Datos SQLite
DB_NAME = "siem_incidents.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            raw_log TEXT,
            severity TEXT,
            ips TEXT,
            technique TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def save_incident(raw_log: str, severity: str, ips: list, technique: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incidents (timestamp, raw_log, severity, ips, technique)
        VALUES (?, ?, ?, ?, ?)
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), raw_log, severity, ", ".join(ips), technique))
    conn.commit()
    conn.close()

def get_recent_incidents():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT 5')
    rows = cursor.fetchall()
    conn.close()
    return rows

def analyze_log_logic(raw_log: str) -> dict:
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips_found = list(set(re.findall(ip_pattern, raw_log)))
    
    log_lower = raw_log.lower()
    if any(keyword in log_lower for keyword in ["critical", "fatal", "root", "unauthorized", "breach"]):
        severity = "CRITICAL"
        threat_technique = "T1078 - Valid Accounts / Privilege Escalation"
    elif any(keyword in log_lower for keyword in ["error", "fail", "denied", "warning"]):
        severity = "MEDIUM"
        threat_technique = "T1110 - Brute Force"
    else:
        severity = "LOW"
        threat_technique = "T1082 - System Information Discovery"

    threats = [
        {
            "severity": severity,
            "tactic": "Defense Evasion / Discovery",
            "technique": threat_technique
        }
    ]
    
    recommendations = [
        f"Verificar la actividad de las IPs detectadas: {ips_found if ips_found else 'Ninguna IP externa identificada'}.",
        "Revisar los registros de auditoría asociados en busca de persistencia."
    ]
    
    # Guardar automáticamente en la base de datos
    save_incident(raw_log, severity, ips_found, threat_technique)
    
    return {
        "ips": ips_found,
        "severity": severity,
        "threats": threats,
        "recommendations": recommendations
    }

@app.get("/")
async def index(request: Request):
    history = get_recent_incidents()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"result": None, "raw_log": "", "history": history}
    )

@app.post("/analyze")
async def analyze(request: Request, raw_log: str = Form(...)):
    analysis_data = analyze_log_logic(raw_log)
    history = get_recent_incidents()
    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "result": analysis_data,
            "raw_log": raw_log,
            "history": history
        }
    )