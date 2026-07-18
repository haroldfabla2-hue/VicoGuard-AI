"""
VicoGuard AI — Security Scanner (Motor de Escaneo)
===================================================
Este módulo ejecuta el escaneo de seguridad contra una URL objetivo.
Cristhian: Aquí van tus scripts de análisis ofensivo.

Funcionalidades:
- Análisis de cabeceras HTTP (seguridad)
- Detección de secretos expuestos en el frontend (API keys, tokens)
- Verificación de configuración Supabase RLS
- Escaneo de puertos básico
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import json


class SecurityScanner:
    """Motor de escaneo de seguridad para aplicaciones web."""

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.findings = []
        self.headers_response = {}

    def run_full_scan(self) -> dict:
        """Ejecuta todas las verificaciones y devuelve resultados estructurados."""
        print(f"[*] Iniciando escaneo de: {self.target_url}")

        self._check_http_headers()
        self._check_exposed_secrets()
        self._check_supabase_rls()
        self._check_directory_exposure()

        return {
            "target_url": self.target_url,
            "findings": self.findings,
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in self.findings if f["severity"] == "HIGH"),
            "medium_count": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
        }

    def _check_http_headers(self):
        """Verifica cabeceras de seguridad HTTP."""
        print("[*] Verificando cabeceras HTTP de seguridad...")
        try:
            resp = requests.get(self.target_url, timeout=10)
            self.headers_response = dict(resp.headers)

            security_headers = {
                "X-Frame-Options": "Protección contra clickjacking",
                "X-Content-Type-Options": "Protección contra MIME sniffing",
                "Strict-Transport-Security": "Fuerza conexión HTTPS",
                "Content-Security-Policy": "Política de seguridad de contenido",
                "X-XSS-Protection": "Protección contra XSS",
            }

            for header, description in security_headers.items():
                if header.lower() not in [h.lower() for h in resp.headers]:
                    self.findings.append({
                        "id": f"VG-HDR-{header[:3].upper()}",
                        "severity": "MEDIUM",
                        "title_technical": f"Missing {header} header",
                        "title_business": f"Tu sitio web carece de una protección de seguridad: {description}",
                        "category": "HTTP_HEADERS",
                    })
        except requests.RequestException as e:
            print(f"[!] Error al conectar: {e}")

    def _check_exposed_secrets(self):
        """Busca secretos expuestos en el código fuente del frontend."""
        print("[*] Buscando secretos expuestos en el frontend...")
        try:
            resp = requests.get(self.target_url, timeout=10)
            html = resp.text

            # Patrones de secretos comunes
            secret_patterns = [
                (r'(?:supabase|SUPABASE).*?(?:anon|service_role).*?["\']([a-zA-Z0-9._\-]{30,})["\']', "Supabase Key"),
                (r'(?:firebase|FIREBASE).*?["\']([A-Za-z0-9_\-]{20,})["\']', "Firebase Key"),
                (r'sk[-_](?:live|test)[-_][a-zA-Z0-9]{20,}', "Stripe Secret Key"),
                (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Hardcoded Password"),
                (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
            ]

            for pattern, name in secret_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    self.findings.append({
                        "id": f"VG-SEC-{name[:3].upper()}",
                        "severity": "CRITICAL" if "service_role" in name.lower() or "secret" in name.lower() else "HIGH",
                        "title_technical": f"Exposed {name} in client-side code",
                        "title_business": f"Se encontró una llave secreta ({name}) visible en el código de tu página. Cualquiera puede copiarla.",
                        "category": "EXPOSED_SECRETS",
                        "evidence": f"Patrón detectado: {name}",
                    })

            # Buscar en archivos JavaScript enlazados
            soup = BeautifulSoup(html, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("/") or src.startswith("http"):
                    full_url = src if src.startswith("http") else f"{self.target_url}{src}"
                    try:
                        js_resp = requests.get(full_url, timeout=10)
                        for pattern, name in secret_patterns:
                            if re.search(pattern, js_resp.text, re.IGNORECASE):
                                self.findings.append({
                                    "id": f"VG-JS-{name[:3].upper()}",
                                    "severity": "HIGH",
                                    "title_technical": f"Exposed {name} in JS bundle: {src}",
                                    "title_business": f"Se encontró una llave ({name}) dentro de un archivo JavaScript ({src}). Esto es visible para cualquiera.",
                                    "category": "EXPOSED_SECRETS_JS",
                                })
                    except requests.RequestException:
                        pass

        except requests.RequestException as e:
            print(f"[!] Error buscando secretos: {e}")

    def _check_supabase_rls(self):
        """Verifica si una app Supabase tiene RLS deshabilitado."""
        print("[*] Verificando configuración de Supabase RLS...")
        try:
            resp = requests.get(self.target_url, timeout=10)
            html = resp.text

            anon_key_match = re.search(r'eyJ[a-zA-Z0-9_\-]{50,}', html)
            if not anon_key_match:
                return  # sin anon key no se puede probar el REST de Supabase
            anon_key = anon_key_match.group(0)

            # Bases REST a probar. Una app puede declarar su base explícita
            # (self-hosted / demo local) con `SUPABASE_REST_BASE = "..."`; si lo
            # hace, tiene prioridad y evita golpear el host cloud (más rápido).
            rest_bases = []
            explicit = re.search(r'SUPABASE_REST_BASE\s*[:=]\s*["\']([^"\']+)["\']', html)
            if explicit:
                base = explicit.group(1).rstrip("/")
                if base.startswith("/"):
                    parsed = urlparse(self.target_url)
                    base = f"{parsed.scheme}://{parsed.netloc}{base}"
                rest_bases.append(base)
            else:
                cloud = re.search(r'https://([a-z0-9]+)\.supabase\.co', html)
                if cloud:
                    rest_bases.append(cloud.group(0))

            if not rest_bases:
                return

            # Intentar consultar tablas comunes sin autenticación
            test_tables = ["users", "customers", "profiles", "orders", "products"]
            for rest_base in rest_bases:
                for table in test_tables:
                    api_url = f"{rest_base}/rest/v1/{table}?select=*&limit=1"
                    headers = {
                        "apikey": anon_key,
                        "Authorization": f"Bearer {anon_key}",
                    }
                    try:
                        test_resp = requests.get(api_url, headers=headers, timeout=5)
                        if test_resp.status_code == 200 and test_resp.text.strip() != "[]":
                            data = test_resp.json()
                            if isinstance(data, list) and len(data) > 0:
                                self.findings.append({
                                    "id": "VG-RLS-001",
                                    "severity": "CRITICAL",
                                    "title_technical": f"Supabase RLS Disabled on '{table}' table",
                                    "title_business": f"La tabla '{table}' de tu base de datos está COMPLETAMENTE EXPUESTA. Cualquier persona puede leer todos los datos sin contraseña.",
                                    "category": "SUPABASE_RLS",
                                    "evidence": f"Se pudieron leer {len(data)} registros de la tabla '{table}' sin autenticación.",
                                    "remediation_code": f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY \"Solo usuarios autenticados\"\n  ON {table} FOR SELECT\n  USING (auth.uid() IS NOT NULL);",
                                })
                    except requests.RequestException:
                        pass

        except requests.RequestException as e:
            print(f"[!] Error verificando Supabase: {e}")

    def _check_directory_exposure(self):
        """Verifica si hay directorios sensibles expuestos."""
        print("[*] Verificando directorios expuestos...")
        sensitive_paths = [
            ("/.env", "Variables de entorno con secretos"),
            ("/.git/config", "Repositorio Git expuesto"),
            ("/wp-admin", "Panel de WordPress"),
            ("/admin", "Panel de administración"),
            ("/api/debug", "Endpoint de debug"),
            ("/phpmyadmin", "phpMyAdmin expuesto"),
        ]

        for path, description in sensitive_paths:
            try:
                resp = requests.get(f"{self.target_url}{path}", timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    self.findings.append({
                        "id": f"VG-DIR-{path[1:4].upper()}",
                        "severity": "CRITICAL" if ".env" in path or ".git" in path else "HIGH",
                        "title_technical": f"Exposed sensitive path: {path}",
                        "title_business": f"Se encontró un archivo sensible accesible públicamente: {description}",
                        "category": "DIRECTORY_EXPOSURE",
                    })
            except requests.RequestException:
                pass


# --- Uso directo para testing ---
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    scanner = SecurityScanner(target)
    results = scanner.run_full_scan()
    print("\n" + "=" * 60)
    print(f"📊 Resultados del escaneo: {target}")
    print(f"   Total: {results['total_findings']} hallazgos")
    print(f"   Críticos: {results['critical_count']}")
    print(f"   Altos: {results['high_count']}")
    print(f"   Medios: {results['medium_count']}")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False))
