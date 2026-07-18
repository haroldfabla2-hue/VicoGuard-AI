---
name: Obsidian Stealth
colors:
  surface: '#111319'
  surface-dim: '#111319'
  surface-bright: '#37393f'
  surface-container-lowest: '#0c0e13'
  surface-container-low: '#191b21'
  surface-container: '#1e1f25'
  surface-container-high: '#282a30'
  surface-container-highest: '#33353a'
  on-surface: '#e2e2e9'
  on-surface-variant: '#bbcabf'
  inverse-surface: '#e2e2e9'
  inverse-on-surface: '#2e3036'
  outline: '#86948a'
  outline-variant: '#3c4a42'
  surface-tint: '#4edea3'
  primary: '#4edea3'
  on-primary: '#003824'
  primary-container: '#10b981'
  on-primary-container: '#00422b'
  inverse-primary: '#006c49'
  secondary: '#d0bcff'
  on-secondary: '#3c0091'
  secondary-container: '#571bc1'
  on-secondary-container: '#c4abff'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#e29100'
  on-tertiary-container: '#523200'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#6ffbbe'
  primary-fixed-dim: '#4edea3'
  on-primary-fixed: '#002113'
  on-primary-fixed-variant: '#005236'
  secondary-fixed: '#e9ddff'
  secondary-fixed-dim: '#d0bcff'
  on-secondary-fixed: '#23005c'
  on-secondary-fixed-variant: '#5516be'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#111319'
  on-background: '#e2e2e9'
  surface-variant: '#33353a'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.04em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: -0.01em
  label-mono:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: 0em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0em
  headline-md-mobile:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 40px
  gutter: 16px
  margin-mobile: 16px
  margin-desktop: 32px
---

## Brand & Style

The design system is engineered for high-performance security environments, evoking a sense of "Obsidian Stealth." It targets technical operators, security researchers, and AI engineers who require rapid data density without cognitive overload. The aesthetic is heavily inspired by high-utility tools like Linear and Raycast, prioritizing precision, speed, and technical sophistication.

The visual style blends **Minimalism** with **Glassmorphism**. It utilizes a "Deepest Space" canvas to reduce eye strain during long-duration monitoring, layered with translucent surfaces that suggest physical depth. The emotional response is one of calm, absolute control, and surgical precision. Every pixel is intentional, utilizing 1px strokes and sharp execution to reinforce the "AI-driven" nature of the product.

## Colors

The palette is anchored in a monochromatic obsidian base to maximize the "stealth" aesthetic.
- **Canvas:** The foundation is `#080A0F`, providing a near-black depth that makes high-contrast accents pop.
- **Surfaces:** Layered surfaces use `#0F131C` for primary containers and `#161C28` for elevated components like modals or popovers.
- **Accents:** 
    - **Cyber Emerald (#10B981):** Used for "Secure," "Active," and "Positive Action" states.
    - **Electric Violet (#8B5CF6):** Used for "AI Reasoning," "Insight," and "Primary Selection."
    - **Danger Crimson (#FF3B5C):** Reserved for "Threats," "Critical Errors," and "Destructive Actions."
    - **Warning Amber (#F59E0B):** Used for "Anomalies" and "Pending Alerts."

## Typography

The typography system utilizes a dual-font approach to separate UI navigation from technical data.
- **Inter:** The primary workhorse for the UI. It should be set with **tight tracking** (negative letter spacing) to achieve the sleek, modern look seen in high-end productivity tools.
- **JetBrains Mono:** Dedicated to log streams, code snippets, sensor data, and "pills" that represent raw system values. This font ensures perfect legibility for character-sensitive technical strings.

Scale hierarchy is intentionally flat to maintain density. Avoid oversized headings in dashboards; prioritize `headline-sm` and `label-mono` for most data-driven views.

## Layout & Spacing

This design system employs a **Fluid Grid** model with high information density. The layout is built on a 4px base unit, allowing for granular control over compact interfaces.

- **Desktop:** 12-column grid with 16px gutters. Margins are kept at 32px to allow the "Deepest Space" canvas to frame the content.
- **Sidebars:** Fixed-width sidebars (typically 240px or 64px collapsed) are used for navigation to maximize vertical space for data streams.
- **Density:** Use "Compact" spacing for data tables (8px cell padding) and "Comfortable" spacing for marketing or onboarding pages (24px+).
- **Mobile:** Reflows to a single column with 16px margins; complex data tables should horizontal-scroll within their glass containers rather than stacking.

## Elevation & Depth

Depth is communicated through **Glassmorphism** and 1px "Bespoke Borders" rather than traditional shadows.

1.  **Canvas (Level 0):** `#080A0F`. No blur.
2.  **Base Surface (Level 1):** `#0F131C` with a 1px border `rgba(255,255,255,0.08)`.
3.  **Floating Surface (Level 2):** Use for cards and panels. Background: `rgba(22, 28, 40, 0.7)`. Backdrop Blur: `12px`. Border: `rgba(255,255,255,0.12)`.
4.  **Overlay (Level 3):** Modals and menus. Background: `rgba(22, 28, 40, 0.9)`. Backdrop Blur: `20px`. Border: `rgba(255,255,255,0.2)`.

Shadows, if used, are extremely subtle: `0px 4px 24px rgba(0, 0, 0, 0.5)`. The primary method of separation is the 1px interior stroke which catches the "light" at the edges of the dark glass.

## Shapes

The shape language is precise and architectural. Use **Soft (0.25rem)** roundedness for standard components to maintain a professional, slightly sharp edge. 

- **Small Components (Buttons, Inputs):** 4px (0.25rem) radius.
- **Containers (Cards, Modals):** 8px (0.5rem) radius.
- **System Tags:** 2px radius for a "technical" look, or fully pill-shaped (999px) only for status pips and AI-generated badges.

## Components

- **Buttons:** Solid buttons use the accent colors (`#10B981` or `#8B5CF6`) with white or near-black text. Ghost buttons use the 1px border with a subtle hover fill of `rgba(255,255,255,0.04)`.
- **Inputs:** Dark backgrounds (`#080A0F`) with 1px borders. On focus, the border color changes to Cyber Emerald or Electric Violet with a very faint outer glow (2px blur).
- **Chips/Badges:** Use JetBrains Mono. Threat badges use Danger Crimson text on a `rgba(255, 59, 92, 0.1)` background with a 1px border of the same color.
- **Gauges & Status Pips:** Status pips should feature a "neon glow" filter (`filter: drop-shadow(0 0 4px color)`). Gauges use thin 2px circular strokes.
- **Lists/Tables:** Use "Zebra" striping with `#161C28` for alternating rows. Hover states should use a subtle highlight of `rgba(255,255,255,0.03)`.
- **AI Reasoning Cards:** Elements generated by VicoGuard AI should feature the Electric Violet accent and a slightly higher backdrop blur (24px) to distinguish them from standard system data.