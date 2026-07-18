# 🎯 Datos Mock para la Demo (Datos Falsos para la Presentación)

Este archivo contiene los datos simulados que el equipo debe usar durante la demo en vivo.
**¡VITAL!** Si el internet falla o la API del LLM se cae durante la presentación, estos datos falsos pre-generados salvan la demo.

---

## 1. Resultado Mock del Escaneo Estático (JSON para alimentar al Dashboard)

```json
{
  "target_url": "https://tienda-lima-demo.vercel.app",
  "scan_duration_seconds": 8.4,
  "security_score": 38,
  "overall_status": "CRITICAL",
  "summary": "Tu aplicación tiene una vulnerabilidad crítica: la base de datos de clientes está completamente expuesta a internet. Cualquier persona puede descargar toda tu información sin necesidad de contraseña.",
  "findings": [
    {
      "id": "VG-001",
      "severity": "CRITICAL",
      "title_technical": "Supabase RLS Disabled on 'customers' table",
      "title_business": "Tu lista completa de clientes está expuesta a cualquier persona en internet",
      "analogy": "Es como tener los archivos de todos tus clientes en una mesa en la vereda, sin candado, a la vista de cualquiera que pase.",
      "impact": "Un atacante puede descargar, modificar o borrar todos los datos de tus clientes (nombres, correos, direcciones, teléfonos) sin necesidad de contraseña.",
      "remediation_steps": [
        "1. Ingresa al panel de Supabase (https://supabase.com/dashboard)",
        "2. Ve a Database > Tables > customers",
        "3. Haz clic en 'Enable RLS' (Seguridad a Nivel de Fila)",
        "4. Copia y pega la siguiente política de seguridad en el SQL Editor:"
      ],
      "remediation_code": "ALTER TABLE customers ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY \"Solo usuarios autenticados pueden leer\"\n  ON customers FOR SELECT\n  USING (auth.uid() IS NOT NULL);\n\nCREATE POLICY \"Solo el dueño puede modificar sus datos\"\n  ON customers FOR UPDATE\n  USING (auth.uid() = user_id);",
      "status": "UNRESOLVED"
    },
    {
      "id": "VG-002",
      "severity": "HIGH",
      "title_technical": "Supabase anon key exposed in client-side JavaScript bundle",
      "title_business": "La llave de acceso a tu base de datos está visible en el código de tu página web",
      "analogy": "Es como escribir la contraseña de tu caja fuerte en un cartel pegado en la puerta de tu tienda.",
      "impact": "Cualquier persona puede copiar esta llave y usarla para hacer consultas directas a tu base de datos.",
      "remediation_steps": [
        "1. Esto es normal en Supabase (la llave 'anon' es pública por diseño)",
        "2. PERO solo es seguro si tienes RLS activado (ver VG-001)",
        "3. Verifica que NO estés usando la llave 'service_role' en el frontend"
      ],
      "remediation_code": "// NUNCA hagas esto en el frontend:\n// const supabase = createClient(url, SERVICE_ROLE_KEY) ← PELIGROSO\n\n// Siempre usa la llave anon:\nconst supabase = createClient(url, ANON_KEY) // ← Correcto",
      "status": "UNRESOLVED"
    },
    {
      "id": "VG-003",
      "severity": "MEDIUM",
      "title_technical": "Missing Content-Security-Policy and X-Frame-Options headers",
      "title_business": "Tu página web puede ser 'copiada' y mostrada dentro de una página falsa para engañar a tus clientes",
      "analogy": "Es como si alguien pudiera poner tu tienda dentro de una tienda falsa para confundir a tus clientes y robarles sus datos de pago.",
      "impact": "Un atacante podría insertar tu web dentro de un iframe malicioso para ejecutar ataques de phishing.",
      "remediation_steps": [
        "1. Añade las siguientes cabeceras de seguridad en tu servidor o en vercel.json:"
      ],
      "remediation_code": "// vercel.json\n{\n  \"headers\": [\n    {\n      \"source\": \"/(.*)\",\n      \"headers\": [\n        { \"key\": \"X-Frame-Options\", \"value\": \"DENY\" },\n        { \"key\": \"Content-Security-Policy\", \"value\": \"frame-ancestors 'none'\" }\n      ]\n    }\n  ]\n}",
      "status": "UNRESOLVED"
    }
  ]
}
```

---

## 2. Mensaje Mock para Telegram (Formato Markdown)

```text
🚨 *ALERTA DE SEGURIDAD CRÍTICA* 🚨
━━━━━━━━━━━━━━━━━━━━━━━

📊 *Security Score: 38/100* ⛔

🏪 *Tu aplicación:* tienda-lima-demo.vercel.app

⚠️ *Problema encontrado:*
Tu lista completa de clientes (nombres, correos, direcciones) está *expuesta a cualquier persona en internet*. No se necesita contraseña para acceder.

🔑 *¿Qué significa esto?*
Imagina que los archivos de todos tus clientes están en una mesa en la vereda de tu tienda, sin candado. Cualquiera que pase puede llevárselos.

🛠️ *Solución (copia y pega esto en Supabase):*
```sql
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Solo usuarios autenticados"
  ON customers FOR SELECT
  USING (auth.uid() IS NOT NULL);
```

✅ *¿Ya aplicaste el parche?* Escribe "Listo" y reescanearemos tu app automáticamente.

_Powered by VicoGuard AI 🛡️_
```

---

## 3. Log Mock de Servidor (Para la Demo del Motor de Correlación)

```log
[2026-07-18 14:23:01] 185.234.72.15 - GET /wp-admin HTTP/1.1 404 - "Mozilla/5.0"
[2026-07-18 14:23:01] 185.234.72.15 - GET /wp-login.php HTTP/1.1 404 - "Mozilla/5.0"
[2026-07-18 14:23:02] 91.108.56.200 - GET /xmlrpc.php HTTP/1.1 404 - "Mozilla/5.0"
[2026-07-18 14:23:02] 185.234.72.15 - GET /.env HTTP/1.1 404 - "Mozilla/5.0"
[2026-07-18 14:23:03] 45.33.49.12 - POST /admin/login HTTP/1.1 401 - "Python-urllib/3.9"
[2026-07-18 14:23:03] 45.33.49.12 - POST /admin/login HTTP/1.1 401 - "Python-urllib/3.9"
[2026-07-18 14:23:04] 45.33.49.12 - POST /admin/login HTTP/1.1 401 - "Python-urllib/3.9"
[2026-07-18 14:23:04] 203.0.113.50 - GET /api/products HTTP/1.1 200 - "Chrome/126"
[2026-07-18 14:23:05] 45.33.49.12 - POST /admin/login HTTP/1.1 401 - "Python-urllib/3.9"
[2026-07-18 14:23:05] 45.33.49.12 - POST /admin/login HTTP/1.1 401 - "Python-urllib/3.9"
[2026-07-18 14:23:06] ERROR [database] Connection pool exhausted. Active: 25/25. Waiting: 12.
[2026-07-18 14:23:06] ERROR [database] Query timeout after 30000ms on table 'orders'.
[2026-07-18 14:23:07] 198.51.100.8 - GET / HTTP/1.1 502 - "Chrome/126"
[2026-07-18 14:23:07] 198.51.100.8 - GET / HTTP/1.1 502 - "Chrome/126"
[2026-07-18 14:23:08] WARNING [server] CPU usage at 94%. Memory: 3.8GB/4GB.
```
