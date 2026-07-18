---
name: VicoGuard AI
colors:
  surface: '#0e1511'
  surface-dim: '#0e1511'
  surface-bright: '#343b36'
  surface-container-lowest: '#09100c'
  surface-container-low: '#161d19'
  surface-container: '#1a211d'
  surface-container-high: '#242c27'
  surface-container-highest: '#2f3632'
  on-surface: '#dde4dd'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#dde4dd'
  inverse-on-surface: '#2b322d'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#ffb95f'
  on-secondary: '#472a00'
  secondary-container: '#ee9800'
  on-secondary-container: '#5b3800'
  tertiary: '#ffb3af'
  on-tertiary: '#650911'
  tertiary-container: '#fc7c78'
  on-tertiary-container: '#711419'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#ffddb8'
  secondary-fixed-dim: '#ffb95f'
  on-secondary-fixed: '#2a1700'
  on-secondary-fixed-variant: '#653e00'
  tertiary-fixed: '#ffdad7'
  tertiary-fixed-dim: '#ffb3af'
  on-tertiary-fixed: '#410005'
  on-tertiary-fixed-variant: '#842225'
  background: '#0e1511'
  on-background: '#dde4dd'
  surface-variant: '#2f3632'
  surface-base: '#020617'
  surface-glass: rgba(15, 23, 42, 0.7)
  alert-crimson: '#f43f5e'
  text-primary: '#f8fafc'
  text-secondary: '#94a3b8'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 40px
    fontWeight: '800'
    lineHeight: 48px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  margin-desktop: 32px
  margin-mobile: 16px
  gutter: 24px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
---

# VicoGuard AI Design System

## 1. Brand Personality & Philosophy
- **Identity:** Enterprise-grade security for SMEs.
- **Vibe:** Power meets extreme simplicity. "Red Team" authority with "Vibecoder" ease.
- **Aesthetic:** Ultra-modern dark mode, "Glassmorphism" (frosted glass), and high-contrast neon accents. Think Vercel or Linear with a cyberpunk/hacker undertone.

## 2. Color Palette
- **Background:** `{{COLOR:SURFACE_0:#020617}}` (Deepest Navy/Black)
- **Surface (Glass):** `{{COLOR:SURFACE_1:rgba(15, 23, 42, 0.7)}}` (Translucent Slate)
- **Primary (Cyber Emerald):** `{{COLOR:PRIMARY:#10b981}}` (Emerald Green for safety/CTA)
- **Warning (Alert Crimson):** `{{COLOR:ERROR:#f43f5e}}` (Crimson for critical findings)
- **Accent (Amber):** `{{COLOR:WARNING:#f59e0b}}` (For medium risk)
- **Text Primary:** `{{COLOR:TEXT_PRIMARY:#f8fafc}}` (Slate 50)
- **Text Secondary:** `{{COLOR:TEXT_SECONDARY:#94a3b8}}` (Slate 400)

## 3. Typography
- **Headings:** Inter (Sans-serif), Bold/ExtraBold for headlines.
- **Body:** Inter (Sans-serif), Medium/Regular.
- **Monospaced:** Roboto Mono or JetBrains Mono (For terminal text, URLs, and numbers).

## 4. Components & Patterns
- **Glass Card:** `backdrop-blur-xl bg-white/5 border border-white/10 rounded-2xl shadow-2xl`
- **Glow Button:** High-intensity shadow with `{{COLOR:PRIMARY}}` glow.
- **Input:** Search-bar style, massive, with an focus-ring emerald glow.
- **Visuals:** Pulsing radar, circular progress gauges, and monospaced terminal logs.
