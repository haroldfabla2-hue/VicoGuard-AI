# VicoGuard AI — Manual de Diseño

> Sistema de diseño de la plataforma. Objetivo: una estética **editorial-técnica** de
> nivel estudio (Linear / Stripe / Vanta), no "plantilla de IA". Este documento es la
> fuente de verdad; `assets/styles.css` lo implementa 1:1 con custom properties.

---

## 1. Principios

1. **El color tiene significado, no decora.** Cada tono mapea a un rol (marca, severidad,
   estado). No se usan colores "porque se ven bien".
2. **Contraste cálido/frío intencional.** Superficies *ink* frías (azuladas, casi negras)
   con texto *paper* cálido (marfil). Esa tensión da sensación de material real, no de
   plantilla plana.
3. **Jerarquía por tipografía, no por peso de caja.** Una serif editorial (Fraunces)
   reservada a los momentos "hero"; el resto en una grotesca de ingeniería (IBM Plex Sans).
4. **Hairlines, no sombras dramáticas.** Bordes de 1px y elevación sutil. Cero glows,
   cero glassmorphism, cero gradientes arcoíris.
5. **Restricción.** Un solo acento de marca (azul). El resto del color se "gana" solo
   cuando comunica riesgo o estado.

---

## 2. Color

### 2.1 Base — Ink (superficies, frío azulado)

| Token | Hex | Uso |
|-------|-----|-----|
| `--bg` | `#0A0C11` | Fondo de la app |
| `--bg-1` | `#0E121A` | Fondo elevado / inputs |
| `--surface` | `#131820` | Tarjetas |
| `--surface-1` | `#171D27` | Tarjeta hover / anidada |
| `--surface-2` | `#1D242F` | Chips, avatar |
| `--line` | `#262D39` | Borde hairline |
| `--line-2` | `#333B49` | Borde fuerte / foco neutro |

### 2.2 Texto — Paper (cálido, marfil)

| Token | Hex | Uso |
|-------|-----|-----|
| `--paper` | `#F6F3ED` | Titulares, hero (máx. contraste) |
| `--text` | `#E6E2DA` | Cuerpo |
| `--text-dim` | `#9D988F` | Secundario |
| `--text-mut` | `#6E6A63` | Terciario, eyebrows, placeholders |

> **Regla:** superficies frías + texto cálido. Nunca texto azulado sobre ink azulado
> (se vuelve "tech genérico"). El marfil da calidez editorial.

### 2.3 Marca — Signal Blue (confianza / acción)

| Token | Hex | Uso |
|-------|-----|-----|
| `--blue` | `#4C86FF` | Acción primaria, marca |
| `--blue-bright` | `#6EA0FF` | Iconos/enlaces sobre ink |
| `--blue-deep` | `#3A6DEB` | Hover / pressed |
| `--on-blue` | `#081428` | Texto sobre azul |

Azul = seguridad/confianza (categoría: Cloudflare, Okta, Vanta). Se reserva para
**marca y acciones**, nunca para severidad.

### 2.4 Severidad (semántico, jamás decorativo)

| Rol | Token | Hex | Significado |
|-----|-------|-----|-------------|
| Crítico | `--critical` | `#FF6B6B` | Coral-rojo (más premium que el rojo puro `#EF4444`) |
| Alto | `--high` | `#FF9145` | Naranja señal |
| Medio | `--medium` | `#F4C24E` | Ámbar |
| Bajo / Info | `--low` | `#7FB0FF` | Azul claro |
| Asegurado | `--secure` | `#46D3A0` | Verde esmeralda (estado resuelto) |

Cada uno con `-tint` (fondo ~10% alpha) y `-line` (borde ~30% alpha) para chips y realces.

**Score ring:** `< 50` → crítico · `50–79` → ámbar/alto · `≥ 80` → asegurado.

> **Nota anti-IA:** deliberadamente **no** hay violeta/morado (el tell #1 de las UIs
> generadas por IA). El coral-rojo y el naranja señal están tuneados a mano, no son los
> Tailwind por defecto.

---

## 3. Tipografía

Pairing de tres voces, todas con fallback robusto (degrada bien offline):

| Rol | Familia | Fallback | Dónde |
|-----|---------|----------|-------|
| Display | **Fraunces** (serif variable, eje óptico) | Georgia, serif | Números hero (score, KPI), H1 de auth, quote |
| UI / cuerpo | **IBM Plex Sans** | system-ui | Toda la interfaz |
| Mono | **IBM Plex Mono** | ui-monospace | Terminal, IDs canónicos, código |

Por qué: Plex Sans + Plex Mono son **misma superfamilia** (cohesión de ingeniería) y
Fraunces aporta un contrapunto editorial-humano imposible de confundir con la Inter
de las plantillas de IA. La serif se usa **con moderación** — solo momentos hero.

### Escala (modular)

| Token | Tamaño | Tracking | Uso |
|-------|--------|----------|-----|
| `--fs-display` | `clamp(38px, 5vw, 52px)` | `-0.02em` | Score, hero |
| `--fs-h1` | `28px` | `-0.02em` | Títulos de página |
| `--fs-h2` | `19px` | `-0.01em` | Títulos de sección |
| `--fs-h3` | `15px` | `0` | Subtítulos |
| `--fs-body` | `15px` | `0` | Cuerpo |
| `--fs-small` | `13px` | `0` | Secundario |
| `--fs-micro` | `11.5px` | `0.09em` (mayúsculas) | Eyebrows, chips |

Números siempre con `font-variant-numeric: tabular-nums` (alineación de dígitos).
Titulares con `text-wrap: balance`.

---

## 4. Espaciado, radio, elevación

- **Espaciado:** múltiplos de 4 (`4, 8, 12, 16, 24, 40, 60`).
- **Radio:** `--r-lg 14px` (tarjetas) · `--r 11px` (inputs/botones) · `--r-sm 8px` · pill `999px`.
- **Elevación:** hairline + sombra discreta (`--shadow-1/2`). Sin neón.
- **Foco:** anillo `0 0 0 3px var(--blue-tint)` + borde `--blue`. Accesible y sobrio.

---

## 5. Componentes (specs)

- **Botón primario:** relleno `--blue`, texto `--on-blue`, brillo interno sutil; hover `--blue-deep`.
- **Botón secundario/ghost:** transparente + hairline; hover eleva a `--surface-1`.
- **Input:** `--bg-1`, hairline, focus ring azul.
- **Card:** `--surface` + `--line` + highlight superior 1px (profundidad).
- **KPI:** número en Fraunces (tabular), label con punto de color de rol.
- **Chip de severidad:** `-tint` de fondo, `-line` de borde, texto del rol.
- **Terminal:** casi negro (`#07090D`), Plex Mono, líneas coloreadas por nivel
  (OK=secure, WARN=high, ALERT=critical, REASONING=azul-lila tenue).
- **Auth:** layout editorial a dos columnas; aside con retícula fina + radial contenido;
  quote en Fraunces.

---

## 6. Extensiones futuras

- Tema claro (paper como fondo, ink como texto) usando los mismos roles.
- Auto-hospedar las fuentes (woff2) para independencia total de red.
