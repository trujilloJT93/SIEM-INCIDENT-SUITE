import re
from typing import Dict, Any, List

class SIEMLogEnricher:
    """Motor de parseo, análisis y enriquecimiento de logs de seguridad."""

    IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    MITRE_RULES = [
        {
            "pattern": r"Failed password|authentication failure|invalid user",
            "tactic": "Credential Access",
            "technique": "T1110 - Brute Force",
            "severity": "HIGH",
            "recommendation": "Bloquear IP origen en firewall y forzar cambio de clave de cuentas afectadas."
        },
        {
            "pattern": r"sudo|runas|privilege escalation",
            "tactic": "Privilege Escalation",
            "technique": "T1548 - Abuse Elevation Control Mechanism",
            "severity": "CRITICAL",
            "recommendation": "Aislar host inmediatamente y auditar permisos de usuario / sudoers."
        },
        {
            "pattern": r"SELECT|UNION|INSERT|DROP|OR 1=1",
            "tactic": "Initial Access",
            "technique": "T1190 - Exploit Public-Facing Application (SQLi)",
            "severity": "CRITICAL",
            "recommendation": "Ajustar reglas de WAF y sanitizar entradas en la base de datos."
        },
        {
            "pattern": r"powershell -e|cmd\.exe /c|bash -i",
            "tactic": "Execution",
            "technique": "T1059 - Command and Scripting Interpreter",
            "severity": "HIGH",
            "recommendation": "Analizar procesos hijos e implementar Constrained Language Mode."
        }
    ]

    def extract_ips(self, text: str) -> List[str]:
        found = re.findall(self.IP_REGEX, text)
        return list(set(found))

    def process(self, raw_log: str) -> Dict[str, Any]:
        threats = []
        max_severity = "LOW"
        recommendations = set()

        for rule in self.MITRE_RULES:
            if re.search(rule["pattern"], raw_log, re.IGNORECASE):
                threats.append({
                    "tactic": rule["tactic"],
                    "technique": rule["technique"],
                    "severity": rule["severity"]
                })
                recommendations.add(rule["recommendation"])

                if rule["severity"] == "CRITICAL":
                    max_severity = "CRITICAL"
                elif rule["severity"] == "HIGH" and max_severity != "CRITICAL":
                    max_severity = "HIGH"

        ips = self.extract_ips(raw_log)

        if not threats:
            threats.append({
                "tactic": "Informational",
                "technique": "T1082 - System Information Discovery",
                "severity": "LOW"
            })
            recommendations.add("Monitorear el evento en busca de patrones anómalos futuros.")

        return {
            "ips": ips,
            "threats": threats,
            "severity": max_severity,
            "recommendations": list(recommendations)
        }
