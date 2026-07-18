# Endurecimiento de producción — VicoGuard AI

La app ya emite cabeceras de seguridad (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) desde un middleware, y cierra `/docs` por defecto.
Estas son las piezas que dependen del entorno / proxy.

## Variables de entorno (prod)

```bash
OPENAI_API_KEY=sk-...            # análisis GPT real (ya configurado en vico.unityiris.com)
VG_ENABLE_DOCS=0                 # Swagger cerrado (default). Poner 1 solo en dev.
VG_COOKIE_SECURE=1               # fuerza cookie Secure (además, se detecta HTTPS por X-Forwarded-Proto)
```

> Telegram ya **no** se configura por `.env`: cada usuario pone su propio bot token y chat ID
> desde **Configuración** en el dashboard (aislado por cuenta).

## uvicorn detrás del proxy

Corre uvicorn confiando en las cabeceras del proxy y sin filtrar su versión:

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 \
  --proxy-headers --forwarded-allow-ips="*" --no-server-header
```

- `--proxy-headers` + `--forwarded-allow-ips` → respeta `X-Forwarded-Proto` (cookie Secure correcta).
- `--no-server-header` → elimina `Server: uvicorn` (evita filtrar el stack).

## Caddy (defensa en profundidad + strip Server)

```caddy
vico.unityiris.com {
    encode zstd gzip
    header {
        -Server                      # oculta cualquier Server upstream
        # (las de seguridad ya vienen del app; puedes reforzarlas aquí si quieres)
    }
    reverse_proxy 127.0.0.1:8000 {
        header_up X-Forwarded-Proto {scheme}
    }
}
```

## Checklist de verificación

```bash
curl -sI https://vico.unityiris.com/ui/login | grep -iE "content-security|strict-transport|x-frame"
curl -s -o /dev/null -w "%{http_code}\n" https://vico.unityiris.com/docs      # -> 404
```

## Notas
- `/demo/vulnerable` y `/demo/supabase/*` se dejan públicos **a propósito** (son el target de
  demo con datos falsos y el scanner los consume server-to-server). Si no quieres exponerlos,
  ponlos tras un flag y desactívalos cuando no haya pitch.
