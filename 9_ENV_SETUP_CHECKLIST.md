# 🔧 Variables de Entorno y Configuración Rápida

Archivo de referencia para configurar todas las credenciales necesarias al inicio de la hackatón.
**Crear un archivo `.env` en la raíz del proyecto con estas variables.**

```env
# ============================================
# VicoGuard AI - Environment Variables
# ============================================

# --- AI Engine (Elegir UNO) ---
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# GOOGLE_AI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxx

# --- Telegram Bot ---
# Crear bot en https://t.me/BotFather -> /newbot
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ
TELEGRAM_CHAT_ID=          # Obtener con /start al bot y luego: https://api.telegram.org/bot<TOKEN>/getUpdates

# --- WhatsApp (Twilio) - Futuro, no necesario para MVP ---
# TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# TWILIO_WHATSAPP_FROM=whatsapp:+14155238886

# --- Email (Resend) - Futuro, no necesario para MVP ---
# RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# --- App Config ---
DEBUG=True
SECRET_KEY=tu-clave-secreta-para-django-cambiar-en-produccion
ALLOWED_HOSTS=localhost,127.0.0.1
```

---

## Checklist de Configuración (Fase 1 - Primeras 30 minutos)

- [ ] Crear repositorio en GitHub (nombre sugerido: `vicoguard-ai`)
- [ ] Clonar en todas las máquinas del equipo
- [ ] Crear bot de Telegram en @BotFather y obtener el Token
- [ ] Obtener `CHAT_ID` enviando `/start` al bot y consultando `getUpdates`
- [ ] Obtener API Key de OpenAI o Google AI Studio
- [ ] Crear archivo `.env` con las variables de arriba
- [ ] Añadir `.env` al `.gitignore` (¡CRÍTICO! No subir secretos a GitHub)
- [ ] Verificar que Python 3.12+ esté instalado en todas las máquinas
- [ ] Instalar dependencias base: `pip install django requests beautifulsoup4 openai python-telegram-bot python-dotenv`
- [ ] Probar que el bot de Telegram responde (enviar mensaje de prueba con `requests.post`)
