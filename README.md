# 🛡️ VicoGuard AI — Hackathon FLIT 2026

> **Agente Autónomo de Ciberseguridad para Pymes**
> Escaneo + Monitoreo de Servidores + Correlación IA + Auto-Remediación por Telegram

---

## 🚀 Quick Start (Primeros 30 minutos)

1. Lee el **[9_ENV_SETUP_CHECKLIST.md](9_ENV_SETUP_CHECKLIST.md)** y configura las variables de entorno
2. Instala dependencias: `pip install -r requirements.txt`
3. Prueba el bot de Telegram: `python scripts/test_telegram.py`
4. Levanta el servidor: `python manage.py runserver`

---

## 📂 Estructura del Proyecto

### 📄 Documentación (Leer en este orden)
| # | Archivo | Para quién | Contenido |
|---|---------|-----------|-----------|
| 1 | [1_PRODUCT_PITCH.md](1_PRODUCT_PITCH.md) | Todos | Problema, solución 360°, modelo de negocio, coreografía del pitch |
| 2 | [6_TEAM_ROLES.md](6_TEAM_ROLES.md) | Todos | Roles, habilidades y reglas de oro del equipo |
| 3 | [3_HACKATHON_ROADMAP.md](3_HACKATHON_ROADMAP.md) | Todos | Plan hora por hora (12h) con tareas por persona |
| 4 | [2_TECHNICAL_ARCHITECTURE.md](2_TECHNICAL_ARCHITECTURE.md) | Devs | Stack, módulos, triggers, diagrama de flujo |
| 5 | [7_AI_SYSTEM_PROMPTS.md](7_AI_SYSTEM_PROMPTS.md) | Alberto | 3 System Prompts del LLM listos para copiar/pegar |
| 6 | [9_ENV_SETUP_CHECKLIST.md](9_ENV_SETUP_CHECKLIST.md) | Luis | Variables de entorno y checklist de setup |
| 7 | [5_STITCH_COMPONENTS.md](5_STITCH_COMPONENTS.md) | Daniel | Índice de las 11 pantallas HTML exportadas |
| 8 | [8_PITCH_SCRIPT_AND_QA.md](8_PITCH_SCRIPT_AND_QA.md) | Mariana | Guion del pitch + preguntas difíciles del jurado |
| 9 | [10_DEMO_MOCK_DATA.md](10_DEMO_MOCK_DATA.md) | Todos | Datos mock de emergencia para la demo |
| 10 | [4_DESIGN_AND_UI.md](4_DESIGN_AND_UI.md) | Daniel | Filosofía visual y prompts de Stitch |
| 11 | [11_MEGA_STITCH_PROMPTS.md](11_MEGA_STITCH_PROMPTS.md) | Daniel | 4 Mega Prompts para generar pantallas adicionales |

### 🎨 Interfaces (HTML + Tailwind CSS listos)
```
ui_stitch/
├── landing_page_vicoguard_ai/     # Landing Page
├── sign_up_vicoguard_ai/          # Registro
├── login_vicoguard_ai/            # Login
├── forgot_password_vicoguard_ai/  # Recuperar contraseña
├── email_verification_vicoguard_ai/ # Verificación email
├── 2fa_vicoguard_ai/              # Autenticación 2FA
├── vicoguard_ai_security_audit/   # Pantalla de escaneo
├── live_agent_execution_vicoguard_ai/ # Terminal del agente
├── threat_dashboard_vicoguard_ai/ # Dashboard + Security Score
├── secops_assistant_vicoguard_ai/ # Chat IA
└── verification_trust_vicoguard_ai/ # Trust Badge
```

### 💻 Código Base
```
src/
├── manage.py                  # Entry point Django
├── vicoguard/
│   ├── settings.py           # Configuración Django
│   ├── urls.py               # Rutas principales
│   └── wsgi.py
├── scanner/                   # App: Escaneo de vulnerabilidades
│   ├── views.py              # Endpoints API
│   ├── models.py             # Modelos de datos
│   ├── services/
│   │   ├── security_scanner.py  # Motor de escaneo (Cristhian)
│   │   ├── ai_engine.py         # Motor de IA (Alberto)
│   │   └── notifications.py     # Dispatcher omnicanal (Luis)
│   └── urls.py
└── scripts/
    ├── test_telegram.py       # Prueba rápida del bot
    └── mock_server_logs.py    # Generador de logs falsos para demo
```
