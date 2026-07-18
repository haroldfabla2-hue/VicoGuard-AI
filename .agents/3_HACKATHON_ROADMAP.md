# ⏱️ Roadmap de Ejecución (Las 12 Horas de Supervivencia)

Este roadmap es un contrato de ejecución estricto. La regla de oro: **Si no es esencial para el demo, no se programa.**

## 🗺️ Mapa de Dependencias Críticas
Diseño DB (`projects`, `scans`) ➔ API Backend ➔ Frontend UI ➔ Integración LLM ➔ Dispatcher Telegram

---

## 🕒 Fase 1: Cimientos y Core Logic (Horas 0 - 3)

**Checkpoints (Hora 3):**
* [ ] Repositorios creados (Back/Front).
* [ ] Base de datos SQLite corriendo con tablas generadas.
* [ ] Interfaz React montada (Hola Mundo estilizado).

**Tareas por Rol:**
* **Luis (Backend):** Inicialización Django/FastAPI. Diseño del esquema SQLite (Tablas: `projects`, `scans`, `telemetry_events`).
* **Cristhian (Red Team):** Desarrollo de script de escaneo en Python para detectar Supabase RLS sin protección.
* **Alberto (IA):** Diseño del System Prompt. Pruebas de APIs LLM (OpenAI/Gemini) aislando respuestas a JSON puro.
* **Daniel (Frontend):** Levantamiento de Next.js/React. Creación de layouts básicos con Tailwind.
* **Mariana (PM/Pitch):** Creación de OKRs horarios. Esbozar narrativa del Pitch Deck. Vigilar timeboxing.

*🛠️ Contingencia (Plan B): Si la API LLM de OpenAI falla por cuota o latencia, cambiar instantáneamente a Gemini Flash o usar respuestas *hardcodeadas* JSON para el demo.*

---

## 🕒 Fase 2: Construcción y Flujo de Datos (Horas 3 - 7)

**Checkpoints (Hora 7):**
* [ ] Frontend muestra lista de proyectos y simula un "escaneo".
* [ ] Backend recibe el POST de logs simulados de un ataque.
* [ ] El Prompt IA traduce el ataque a lenguaje natural.

**Tareas por Rol:**
* **Luis:** Habilitar endpoints `/api/v1/scan` y `/api/v1/telemetry`.
* **Cristhian:** Montar servidor "Señuelo" vulnerable. Preparar scripts de ataque DDoS/SQLi controlados.
* **Alberto:** Enlazar el flujo: Motor de Triggers -> Llamada a IA -> Generación de Protocolo.
* **Daniel:** Componente Dashboard (Security Score, Gráficos de eventos).
* **Mariana:** Validar UX con usuarios externos/mentores. Refinar modelo de monetización (PLG/SaaS).

*🛠️ Contingencia (Plan B): Si el servidor señuelo da problemas de red (Wi-Fi del evento), atacar localhost y simular el tráfico mediante Postman.*

---

## 🕒 Fase 3: Integración Omnicanal y Demo Path (Horas 7 - 10)

**Checkpoints (Hora 10):**
* [ ] El ataque de Cristhian dispara un JSON al Backend.
* [ ] El celular de Daniel recibe un mensaje de Telegram en menos de 5 segundos.

**Tareas por Rol:**
* **Luis & Alberto:** Integración del Notification Dispatcher. Conectar el bot de Telegram (`python-telegram-bot` o Webhook directo).
* **Cristhian:** Pruebas de fuego al servidor señuelo. Extraer datos para probar que es vulnerable sin VicoGuard.
* **Daniel:** Conexión completa Axios/Fetch entre Frontend y Backend. Feedback visual de carga.
* **Mariana:** Guionización del pitch minuto a minuto (quién tiene el clicker, quién habla). Crear el doc "Defensa Q&A Jurado" (ej. "Diferencias vs Snyk").

*🛠️ Contingencia (Plan B): Si Telegram bloquea el webhook por ngrok, usar long-polling temporalmente o retroceder a Email vía Resend.*

---

## 🕒 Fase 4: Código Congelado, Ensayos y Pitch (Horas 10 - 12)

**Checkpoints (Hora 12):**
* [ ] CODE FREEZE: Prohibido hacer git push de nuevas *features*. Solo corrección de bugs críticos visuales.
* [ ] 3 ensayos completos del Pitch cronometrados.

**Tareas por Rol:**
* **Mariana & Alberto:** Liderar simulacro teatral. Coordinar el momento del "ataque" y el sonido de notificación del teléfono frente al jurado.
* **Cristhian:** Limpiar logs y reiniciar el servidor señuelo a estado 'cero' para la presentación final.
* **Luis & Daniel:** Validación de UI en proyector (colores, contraste, tamaño de letra).
