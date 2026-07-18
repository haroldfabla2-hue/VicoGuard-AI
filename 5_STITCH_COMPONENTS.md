# 🎨 Componentes de Interfaz Generados por Google Stitch (ACTUALIZADO)

Todas las pantallas exportadas desde Google Stitch están en `ui_stitch/`. Cada carpeta contiene un `code.html` (código funcional con Tailwind CSS) y un `screen.png` (captura de alta fidelidad).

---

## 📁 Inventario Completo de Pantallas (11 Interfaces + 2 Design Docs)

### 🏠 Marketing & Entrada
| # | Carpeta | Pantalla | Archivos |
|---|---------|----------|----------|
| 1 | `landing_page_vicoguard_ai/` | **Landing Page Completa** (Hero, Features, Pricing, Footer) | `code.html` + `screen.png` |

### 🔐 Autenticación (Auth Flow)
| # | Carpeta | Pantalla | Archivos |
|---|---------|----------|----------|
| 2 | `sign_up_vicoguard_ai/` | **Registro / Sign Up** | `code.html` + `screen.png` |
| 3 | `login_vicoguard_ai/` | **Login** | `code.html` + `screen.png` |
| 4 | `forgot_password_vicoguard_ai/` | **Recuperar Contraseña** | `code.html` + `screen.png` |
| 5 | `email_verification_vicoguard_ai/` | **Verificación de Email** | `code.html` + `screen.png` |
| 6 | `2fa_vicoguard_ai/` | **Autenticación 2FA** | `code.html` + `screen.png` |

### 🛡️ Core del Producto
| # | Carpeta | Pantalla | Archivos |
|---|---------|----------|----------|
| 7 | `vicoguard_ai_security_audit/` | **Pantalla de Auditoría Inicial** (Input URL + Escaneo) | `code.html` + `screen.png` |
| 8 | `live_agent_execution_vicoguard_ai/` | **Terminal del Agente en Vivo** (Logs + Razonamiento IA) | `code.html` + `screen.png` |
| 9 | `threat_dashboard_vicoguard_ai/` | **Dashboard de Amenazas** (Security Score + Vulnerabilidades) | `code.html` + `screen.png` |
| 10 | `secops_assistant_vicoguard_ai/` | **Asistente IA / Chat SecOps** (Interfaz conversacional) | `code.html` + `screen.png` |
| 11 | `verification_trust_vicoguard_ai/` | **Trust Badge** (Widget de verificación) | `code.html` + `screen.png` |

### 📐 Design System
| # | Carpeta | Contenido |
|---|---------|-----------|
| 12 | `obsidian_stealth/` | `DESIGN.md` — Tokens del Design System (colores, tipografía, espaciado) |
| 13 | `vicoguard_ai/` | `DESIGN.md` — Especificaciones generales de diseño |

---

## 🚀 Cómo Usar Estos Archivos Mañana

### Opción 1: Vista Rápida (Abrir en navegador)
Daniel/Luis pueden abrir cualquier `code.html` directamente en Chrome para ver la interfaz funcionando.

### Opción 2: Integrar en React/Next.js
1. Abrir el `code.html` de la pantalla deseada.
2. Copiar el contenido del `<body>` (los bloques `<section>`, `<main>`, `<div>`).
3. Pegarlo dentro de un componente React (`.jsx`/`.tsx`).
4. Ajustar `class=` por `className=` para React.
5. Las clases de Tailwind CSS funcionan directamente si Tailwind está configurado en el proyecto.

### Opción 3: Integrar en Django Templates
1. Copiar el HTML completo del `code.html`.
2. Pegarlo en un template de Django (ej. `templates/dashboard.html`).
3. Reemplazar datos estáticos con variables de Django (`{{ security_score }}`).
4. Incluir el CDN de Tailwind CSS en el `<head>`.

---

## ⏳ Pantallas Pendientes de Generar en Stitch (Prompts B, C, D del archivo 11_MEGA_STITCH_PROMPTS.md)
- [ ] Onboarding Wizard (4 pasos)
- [ ] Dashboard Principal (Command Center con KPIs)
- [ ] Historial de Escaneos
- [ ] Detalle de Escaneo Individual
- [ ] Lista de Servidores Monitoreados
- [ ] Detalle de Servidor (Métricas + Logs + Timeline de Ataques)
- [ ] Modal de Ataque en Progreso
- [ ] Centro de Notificaciones
- [ ] Preferencias de Notificación (Matriz de Canales)
- [ ] Preview de Plantillas (Telegram, WhatsApp, Email)
- [ ] Account Settings
- [ ] Billing & Pagos
- [ ] Modal de Checkout
- [ ] Dashboard MSSP / Agencias
- [ ] White-Label Branding
- [ ] Estados Vacíos
- [ ] Páginas de Error (404, 500, Mantenimiento)
- [ ] Vistas Mobile Responsive
