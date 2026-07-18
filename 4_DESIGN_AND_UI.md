# 🎨 Arquitectura UI/UX y Diseño (VicoGuard AI)

## 1. Filosofía de Diseño (UX)
El producto está dirigido a fundadores de Pymes y "Vibecoders". El diseño debe transmitir dos cosas: **Poder (Ciberseguridad)** y **Facilidad extrema**.
* **Tema Visual:** Dark Mode nativo (Fondo oscuro, tipografía limpia, acentos en neón verde/ámbar para simular terminales modernas sin ser ruidosas). Estilo "Glassmorphism" (efecto cristal translúcido) para un toque premium.
* **Fricción Cero:** Nada de registros largos. La pantalla principal es literalmente una barra de búsqueda glorificada (estilo Google o Perplexity).

## 2. Mapa de Pantallas (Vistas del MVP)

### Vista 1: Landing Page (El Punto de Entrada)
* **Hero Section:** Título audaz ("Seguridad de nivel Red Team para tu Pyme en 1 minuto"). Subtítulo explicativo.
* **Input Principal:** Una barra de entrada de texto gigante en el centro para ingresar la `URL del proyecto`.
* **Input Secundario (Opcional):** Un campo pequeño para ingresar el `Token de Telegram` y recibir la alerta móvil.
* **Call to Action (CTA):** Botón grande que dice "Auditar mi App Ahora" con un ícono de escudo o radar.

### Vista 2: Estado de Carga Dinámico (El Factor Psicológico)
* Mientras el backend trabaja (los 5-10 segundos que toma la IA), la pantalla no debe quedarse estática.
* **Visual:** Un radar escaneando o una terminal de código desvaneciéndose en el fondo.
* **Texto Dinámico:** Mensajes que cambian cada 2 segundos: 
  * *"Mapeando superficie pública..."*
  * *"Buscando secretos expuestos..."*
  * *"Analizando dependencias con IA..."*

### Vista 3: El Dashboard de Resultados (La Revelación)
* **Header:** El "Security Score" gigante. Un número del 0 al 100.
  * *Verde:* Seguro.
  * *Ámbar/Rojo:* Crítico.
* **Body:** Lista de hallazgos. Cada tarjeta (card) no tiene jerga técnica en el título, sino el impacto de negocio (Ej: "Tu base de clientes está pública").
* **Footer:** Una llamada a la acción para "Ver detalles en Telegram" (lo que conecta con la historia del teléfono sonando en vivo).

---

## 3. EL SÚPER PROMPT PARA GOOGLE STITCH

*Instrucciones: Copia y pega exactamente este prompt en **Google Stitch** (stitch.withgoogle.com) para generar el código frontend de la aplicación con la más alta calidad posible.*

```text
Create a premium, modern, and highly interactive web application interface for an AI-powered cybersecurity platform named "VicoGuard AI". The target audience is non-technical founders and SME owners. The aesthetic must be ultra-modern, relying on a sleek Dark Mode (deep blacks, slate grays) with "glassmorphism" effects (translucent frosted glass panels) and vibrant neon accents (emerald green for safety, amber/crimson for alerts). The typography must use a clean, futuristic sans-serif font like Inter or Roboto Mono for numbers.

I need three distinct UI states seamlessly integrated into a single-page layout:

1. THE LANDING / INPUT STATE:
- A minimalist, powerful hero section centered on the screen.
- Main Headline: "Enterprise-Grade Red Teaming for your SME, in 60 seconds."
- A prominent, large, and glowing input field (search-bar style) with placeholder text: "Enter your web app URL (e.g., my-store.com)".
- A secondary, smaller input below it for "Telegram Token (for mobile alerts)".
- A bold, glowing CTA button: "Scan My App Now" with a subtle hover animation.

2. THE SCANNING STATE (Loading Simulation):
- Below the input, create a visually captivating loading area.
- Use a skeleton loader or a sweeping radar animation effect.
- Include a dynamic text element displaying changing statuses like: "Mapping public surface...", "Scanning for exposed secrets...", "AI correlating vulnerabilities...".

3. THE RESULTS DASHBOARD STATE (The Reveal):
- A massive, beautiful circular progress indicator displaying a "Security Score" (e.g., 45/100 colored in warning crimson).
- Below the score, a grid of 3 "Vulnerability Cards". 
- Card Design: Frosted glass background, a warning icon, a non-technical business impact title (e.g., "Customer Database is Publicly Accessible"), and a subtle "View Fix on Telegram" badge.
- A "Verified by VicoGuard" trust badge mockup at the bottom.

Overall Vibe: Think of the sleekness of Vercel or Linear, combined with a cyberpunk/hacker undertone, but clean and trustworthy enough for a bank. Provide the HTML, CSS (Tailwind preferred if available), and layout structure. Ensure responsive design and micro-interactions on hover for all clickable elements.
```
