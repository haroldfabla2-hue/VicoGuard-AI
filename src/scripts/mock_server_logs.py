"""
VicoGuard AI — Mock Server Logs Generator
=========================================
Genera logs de servidor simulados para probar la correlación del LLM en vivo.
"""

MOCK_LOGS_SAMPLE = """[2026-07-18 14:23:01] 185.234.72.15 - GET /wp-admin HTTP/1.1 404 - "Mozilla/5.0"
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
[2026-07-18 14:23:08] WARNING [server] CPU usage at 94%. Memory: 3.8GB/4GB."""

def get_mock_logs():
    return MOCK_LOGS_SAMPLE

if __name__ == "__main__":
    print(get_mock_logs())
