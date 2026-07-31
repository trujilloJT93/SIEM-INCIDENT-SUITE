# 🛡️ SIEM & Incident Suite

> Plataforma avanzada de análisis, correlación de eventos y enriquecimiento de logs de seguridad orientada a operaciones SOC.

---

## 🚀 Sobre el Proyecto
**SIEM & Incident Suite** es una herramienta full-stack diseñada para simular y ejecutar capacidades de un Centro de Operaciones de Seguridad (SOC). Permite ingerir logs en bruto, procesarlos mediante expresiones regulares y heurísticas de seguridad para detectar patrones de ataque alineados con **MITRE ATT&CK**, y almacenar de forma persistente el historial de incidentes.

---

## 🛠️ Características Principales
* **Análisis Heurístico de Logs:** Detección automática de anomalías y categorización por niveles de severidad (`LOW`, `MEDIUM`, `CRITICAL`).
* **Extracción de Inteligencia:** Identificación precisa de direcciones IP y mapeo con tácticas y técnicas de **MITRE ATT&CK**.
* **Persistencia Local Segura:** Almacenamiento automático de cada evento analizado en una base de datos **SQLite**.
* **Dashboard Interactivo:** Interfaz web moderna de alta visibilidad desarrollada con Bootstrap y Jinja2.
* **Contenedorización Total:** Listo para ejecutarse de inmediato mediante Docker.

---

## 🧰 Tecnologías Utilizadas
* **Backend:** Python / FastAPI / SQLite
* **Frontend:** Jinja2 / Bootstrap 5 (Dark Mode SOC UI)
* **Despliegue:** Docker & Docker Compose
* **Seguridad:** Regex & MITRE ATT&CK Framework mapping

---

## ⚙️ Guía de Instalación y Despliegue Rápido

Sigue estos pasos para poner en marcha la suite en tu equipo:

1. **Clona el repositorio:**
   ```bash
   git clone [https://github.com/trujilloJT93/SIEM-INCIDENT-SUITE.git](https://github.com/trujilloJT93/SIEM-INCIDENT-SUITE.git)
   cd SIEM-INCIDENT-SUITE
