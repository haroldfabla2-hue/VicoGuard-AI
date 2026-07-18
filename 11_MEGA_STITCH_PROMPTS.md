# 🎨 MEGA PROMPT DEFINITIVO PARA GOOGLE STITCH
## Generación Completa de UI/UX — Todas las Pantallas de VicoGuard AI

---

## INSTRUCCIONES DE USO:
Este documento contiene **4 MEGA PROMPTS** separados para pegar en Google Stitch secuencialmente.
Stitch funciona mejor cuando le das bloques enfocados en lugar de un solo prompt enorme.
**Orden de ejecución:**
1. **Prompt A:** Design System + Landing Page + Auth (Registro, Login, Recuperación)
2. **Prompt B:** Onboarding + Dashboard Principal + Historial + Detalles de Escaneo
3. **Prompt C:** Monitoreo de Servidores + Centro de Notificaciones + Preferencias + Plantillas de Mensajes
4. **Prompt D:** Configuración de Cuenta + Billing/Pagos + Panel MSSP (Agencias) + Trust Badge + Estados Vacíos/Error + Páginas Móviles

---

# ═══════════════════════════════════════════════
# PROMPT A: DESIGN SYSTEM + LANDING + AUTENTICACIÓN
# ═══════════════════════════════════════════════

```text
Act as a Principal Product Designer who has designed award-winning SaaS interfaces for Linear, Raycast, Stripe, Vercel, and Supabase. You are designing the COMPLETE interface for "VicoGuard AI" — an Autonomous AI-Powered Cybersecurity Platform for SMEs. 

CRITICAL ANTI-AI DESIGN RULES:
- NEVER use generic rounded cards with heavy gray shadows. 
- NEVER center everything lazily. Use intentional asymmetry where it adds dynamism.
- USE bespoke, hyper-polished design language inspired by Linear.app (crisp borders, dense data), Stripe (trust-building layouts), and Raycast (command-palette aesthetics).
- Every screen must feel like a $50M funded startup product, NOT a template.

DESIGN SYSTEM TOKENS (Apply to ALL screens):
- Canvas: #080A0F (deepest obsidian black)
- Surface Level 1: #0F131C with border: 1px solid rgba(255,255,255,0.06)
- Surface Level 2: #161C28 (elevated/hover state)
- Surface Level 3: #1E2536 (active/selected state)
- Primary Accent: Cyber Emerald #10B981 (safe, active, CTA)
- Danger: #FF3B5C (critical alerts, exposed vulnerabilities)
- Warning: #F59E0B (suspicious, needs attention)
- AI Reasoning: #8B5CF6 (electric violet, agent thinking)
- Info: #3B82F6 (informational, links)
- Text Primary: #F1F5F9 (slate-100)
- Text Secondary: #94A3B8 (slate-400)
- Text Muted: #475569 (slate-600)
- Typography: 'Inter' for UI, 'JetBrains Mono' for code/data
- Border Radius: 8px for cards, 6px for inputs, 12px for modals
- Glassmorphism: backdrop-blur-xl, bg-opacity-80
- Shadows: Use colored neon glows (drop-shadow with accent colors), NOT gray box-shadows
- All buttons: subtle hover glow + translateY(-1px) transition
- Status pills: small rounded badges with pulse animation for live states

---

GENERATE THE FOLLOWING SCREENS ON THE CANVAS:

### SCREEN A1: MARKETING LANDING PAGE (Full Scroll Page)
Design a premium, conversion-optimized landing page with these sections stacked vertically:

**A1.1 — Navigation Bar (Sticky)**
- Left: VicoGuard AI logo (shield icon + wordmark in emerald gradient)
- Center: Nav links: "Features", "How It Works", "Pricing", "Docs"
- Right: "Login" (ghost button) + "Start Free Audit" (emerald filled button with glow)
- Frosted glass background that becomes opaque on scroll

**A1.2 — Hero Section**
- Left column (60%): 
  - Announcement pill badge: "🔥 Now protecting 2,400+ SMEs across Latin America"
  - Main headline (48px, bold, white): "Your AI Security Team That Never Sleeps"
  - Subheadline (18px, slate-400): "Autonomous penetration testing, real-time server monitoring, and instant remediation — delivered to your phone in plain language. No security expertise required."
  - Two CTAs side by side: "Start Free Audit →" (emerald, large) + "Watch 2-min Demo ▶" (ghost/outline)
  - Social proof row: Small avatars of companies + "Trusted by 2,400+ businesses"
- Right column (40%):
  - Floating mockup of the VicoGuard dashboard showing a Security Score gauge at 92/100 in green, with a Telegram notification popping up from the corner

**A1.3 — Logos Bar**
- "Trusted by innovative companies" with 6 grayscale company logos on dark background

**A1.4 — Problem Statement Section**
- Large stat cards in a 3-column grid:
  - Card 1: "82.8%" with subtext "of AI-generated code contains security vulnerabilities"
  - Card 2: "748M" with subtext "cyberattack attempts in Peru in just 6 months"
  - Card 3: "$2.73M" with subtext "average ransomware payment globally"
- Each card has a subtle red/amber glow to convey danger

**A1.5 — How It Works (3-Step Flow)**
- Horizontal 3-step process with connecting lines/arrows:
  - Step 1: "Paste Your URL" — Icon of a link/globe. "Enter your web app URL or connect your repository."
  - Step 2: "AI Agents Attack" — Icon of a radar/shield. "Our autonomous agents scan, reason, and verify vulnerabilities like a real hacker."
  - Step 3: "Get the Fix on Your Phone" — Icon of a phone with Telegram. "Receive plain-language alerts and exact remediation code on Telegram, WhatsApp, or Email."

**A1.6 — Features Grid (2x3)**
- 6 feature cards with frosted glass background, icon, title, description:
  1. "Pre-Deployment Scanning" — Detect secrets, misconfigurations, and exposed databases before you go live.
  2. "24/7 Server Monitoring" — Continuous watching of logs, traffic spikes, brute force attempts, and server health.
  3. "AI Attack Correlation" — Instead of 500 noisy alerts, get ONE intelligent summary of what actually matters.
  4. "Auto-Remediation" — Receive the exact SQL query, bash command, or config change to fix each vulnerability.
  5. "Omnichannel Alerts" — Choose Telegram, WhatsApp, or Email. Get alerts where you already are.
  6. "Trust Badge" — Earn a "Verified Secure" badge to display on your website and build customer confidence.

**A1.7 — Interactive Demo Preview**
- Dark embedded browser mockup showing the scanning terminal with green monospaced text streaming live. Make it look like a sophisticated command center, not a boring screenshot.

**A1.8 — Pricing Section**
Design 3 pricing cards side by side:
- **Free Plan (Starter):**
  - $0/month
  - 1 monthly surface scan
  - Email alerts only
  - Basic Security Score
  - CTA: "Start Free" (outline button)
- **Pro Plan (Most Popular — highlighted with emerald border glow):**
  - $39/month
  - Unlimited scans
  - 24/7 server monitoring
  - Real-time Telegram + WhatsApp alerts
  - AI auto-remediation with code patches
  - Trust Badge
  - Scan history & compliance reports
  - CTA: "Start 14-Day Trial" (filled emerald button)
- **Agency / MSSP:**
  - Custom pricing
  - White-label dashboard
  - Multi-tenant management
  - Volume licensing
  - Priority support
  - CTA: "Contact Sales" (outline button)
- Toggle switch above: "Monthly / Annual (Save 20%)"

**A1.9 — Testimonials / Social Proof**
- 3 testimonial cards with avatar, name, company, quote. Dark glass cards.
  - "VicoGuard found a critical database exposure in my Supabase app that I had no idea existed. The Telegram alert saved my business." — María, Founder @ TiendaLima
  - "We replaced a $5,000/year penetration testing contract with VicoGuard Pro. Same coverage, 100x faster." — Carlos, CTO @ FinTech Peru
  - "The plain-language explanations are incredible. I'm not a developer, but I fixed the vulnerability myself in 5 minutes." — Andrés, Owner @ RestaurantApp

**A1.10 — Footer**
- 4-column footer: Product (Features, Pricing, Docs, Status), Company (About, Blog, Careers, Press), Legal (Privacy, Terms, Security), Connect (Twitter/X, LinkedIn, GitHub)
- Bottom bar: © 2026 VicoGuard AI. "Built in Arequipa, Peru 🇵🇪"

---

### SCREEN A2: REGISTRATION / SIGN UP PAGE
- Split layout:
  - Left panel (45%): Dark branded panel with VicoGuard logo, headline "Protect your app in 60 seconds", bullet points of value props, and background mesh gradient (emerald + violet, very subtle)
  - Right panel (55%): Clean registration form on elevated surface:
    - "Create your account" headline
    - Full Name input field
    - Work Email input field
    - Password input field (with strength indicator bar below: weak=red, medium=amber, strong=green)
    - Company Name input field (optional, with "Optional" label)
    - Checkbox: "I agree to the Terms of Service and Privacy Policy"
    - CTA Button: "Create Account" (full width, emerald)
    - Divider: "── or continue with ──"
    - OAuth buttons: "Continue with Google" (outlined) + "Continue with GitHub" (outlined)
    - Bottom text: "Already have an account? Log in"

### SCREEN A3: LOGIN PAGE
- Same split layout as registration
  - Left panel: Same branding but with different headline: "Welcome back, defender."
  - Right panel: Login form:
    - "Sign in to VicoGuard" headline
    - Email input
    - Password input (with show/hide toggle icon)
    - Row: Checkbox "Remember me" + Link "Forgot password?"
    - CTA: "Sign In" (emerald, full width)
    - Divider + OAuth buttons (Google, GitHub)
    - Bottom: "Don't have an account? Sign up free"

### SCREEN A4: FORGOT PASSWORD PAGE
- Centered card on dark canvas:
  - Lock icon (large, emerald)
  - "Reset your password" headline
  - "Enter your email and we'll send you a reset link." subtitle
  - Email input field
  - CTA: "Send Reset Link" (emerald)
  - Link: "← Back to login"

### SCREEN A5: EMAIL VERIFICATION PAGE
- Centered card:
  - Mail icon with checkmark (large, emerald)
  - "Check your inbox" headline
  - "We've sent a verification link to alberto@vicoguard.ai" subtitle
  - "Didn't receive it?" link + "Resend email" button (ghost)
  - Progress dots showing step 1 of 3 in onboarding

### SCREEN A6: TWO-FACTOR AUTHENTICATION (2FA)
- Centered card:
  - Shield lock icon
  - "Two-Factor Authentication" headline
  - "Enter the 6-digit code from your authenticator app" subtitle
  - 6 individual square digit input boxes (monospaced font, large)
  - CTA: "Verify" (emerald)
  - Link: "Use backup code instead"
  - Link: "← Back to login"
```

---

# ═══════════════════════════════════════════════
# PROMPT B: ONBOARDING + DASHBOARD + HISTORIAL + DETALLE
# ═══════════════════════════════════════════════

```text
Continue designing the VicoGuard AI platform using the exact same Design System tokens (Obsidian canvas #080A0F, Emerald #10B981, Crimson #FF3B5C, Inter + JetBrains Mono, glassmorphism, neon glows). Generate the following screens:

### SCREEN B1: ONBOARDING WIZARD — STEP 1: ADD YOUR FIRST ASSET
- Progress bar at top showing Step 1 of 4 (emerald progress)
- Centered card:
  - "Let's protect your first app" headline
  - "What type of asset do you want to monitor?" subtitle
  - 3 large selectable option cards (radio-style, highlight border on select):
    - 🌐 "Web Application" — "I have a live website or web app (URL)"
    - 📦 "Repository" — "I want to scan my source code (GitHub/GitLab)"
    - 🖥️ "Server / VPS" — "I want to monitor my server health and security"
  - CTA: "Continue →" (emerald)
  - Link: "Skip for now"

### SCREEN B2: ONBOARDING WIZARD — STEP 2: ENTER URL / CONNECT REPO
- Progress bar: Step 2 of 4
- Centered card:
  - "Enter your app URL" headline
  - Large, prominent input field: "https://your-app.com"
  - OR divider
  - "Connect your repository" with GitHub and GitLab OAuth buttons
  - CTA: "Continue →"

### SCREEN B3: ONBOARDING WIZARD — STEP 3: CONNECT NOTIFICATIONS
- Progress bar: Step 3 of 4
- "Where should we send alerts?" headline
- 3 notification channel cards (multi-select with checkboxes):
  - 📱 Telegram: Input for Bot Token + "How to get your token" help link. Status: "Not connected" (gray) or "Connected ✓" (emerald)
  - 💬 WhatsApp: Phone number input + "Connect via Twilio" button. Status badge.
  - 📧 Email: Already pre-filled with registration email. Toggle on/off. Status: "Active ✓"
- Each card has a "Test Connection" button that sends a test message
- CTA: "Continue →"

### SCREEN B4: ONBOARDING WIZARD — STEP 4: FIRST SCAN
- Progress bar: Step 4 of 4 (complete!)
- "You're all set! Launch your first security audit?" headline
- Summary card showing: Asset URL, Connected channels (Telegram ✓, Email ✓)
- Large CTA: "🚀 Launch First Audit" (emerald, with pulse animation)
- Secondary link: "I'll do it later, take me to dashboard"

---

### SCREEN B5: MAIN DASHBOARD (Command Center — Post-Onboarding)
This is the PRIMARY screen users see after login. Design it as a dense but clean command center:

**B5.1 — Left Sidebar (Narrow, 64px collapsed / 240px expanded)**
- Top: VicoGuard logo (small)
- Navigation icons (vertical):
  - 🏠 Dashboard (active state: emerald left border + emerald icon)
  - 🔍 Scans
  - 🖥️ Servers
  - 🔔 Notifications
  - 💬 AI Assistant
  - 🛡️ Trust Badge
  - ⚙️ Settings
- Bottom: User avatar + name dropdown
- Collapse/expand toggle

**B5.2 — Top Bar**
- Left: "Dashboard" page title + breadcrumb
- Center: Global search bar (command palette style, "Search assets, scans, alerts..." with ⌘K shortcut hint)
- Right: Notification bell (with red dot badge for unread) + "New Scan" button (emerald)

**B5.3 — Main Content Area**
- **Row 1: KPI Cards (4 columns)**
  - Card 1: "Overall Security Score" — Large "72/100" with circular gauge, amber color, trend arrow "↑ +5 from last week"
  - Card 2: "Active Threats" — "2" in crimson with pulse dot, "1 Critical, 1 Medium"
  - Card 3: "Assets Monitored" — "3" with globe icon, "2 Web Apps, 1 Server"
  - Card 4: "Scans This Month" — "12" with chart sparkline showing scan frequency

- **Row 2: Two-column layout**
  - Left (65%): "Recent Scan Results" — Table/list:
    | Status | Asset | Score | Threats | Date | Action |
    | 🔴 Critical | tienda-lima.com | 38/100 | 3 | 2h ago | View → |
    | 🟡 Warning | api.miapp.pe | 65/100 | 1 | 1d ago | View → |
    | 🟢 Secure | blog.empresa.com | 94/100 | 0 | 3d ago | View → |
    Each row has hover highlight state.
  - Right (35%): "Live Server Status" — Compact cards:
    - Server 1: "prod-server-01" — 🟢 Online, CPU 34%, RAM 2.1/4GB, Uptime 99.9%
    - Server 2: "staging-01" — 🟡 High Load, CPU 87%, RAM 3.6/4GB

- **Row 3: Activity Feed + Quick Actions**
  - Left: "Recent Activity" timeline:
    - "🚨 Critical vulnerability found in tienda-lima.com — 2h ago"
    - "✅ Scan completed for api.miapp.pe — 1d ago"  
    - "🛡️ Trust Badge renewed for blog.empresa.com — 3d ago"
    - "⚡ Brute force attempt blocked on prod-server-01 — 5d ago"
  - Right: Quick action buttons: "Run New Scan", "Add Server", "View Alerts"

---

### SCREEN B6: SCAN HISTORY PAGE
- Same sidebar + top bar layout
- Page title: "Scan History"
- Filter bar: Date range picker + Asset dropdown + Severity filter (All, Critical, High, Medium, Low) + Search
- Results table (full width):
  | # | Asset | Type | Score | Critical | High | Medium | Duration | Date | Actions |
  With sortable column headers, pagination at bottom, and "Export CSV" button

### SCREEN B7: INDIVIDUAL SCAN DETAIL PAGE
- Same sidebar layout
- Header: Asset URL + Scan date + Duration + "Re-scan" button
- Top: Large Security Score gauge (circular, animated) + Score breakdown bar (Critical red, High orange, Medium amber, Low blue, Info gray)
- Tab navigation: "Vulnerabilities" (active) | "Raw Data" | "Remediation Report" | "Timeline"
- Vulnerabilities tab content:
  - Expandable accordion cards for each finding:
    - Header: Severity badge (🔴 CRITICAL) + Business-language title + Collapse/expand chevron
    - Expanded content:
      - "What this means for your business:" paragraph with analogy
      - "Technical Details:" collapsible section with monospaced technical info
      - "How to fix it:" numbered steps
      - Code diff block: Left (vulnerable code, red highlight) → Right (patched code, green highlight)
      - "Send Fix to Telegram" button + "Mark as Resolved" button
      - Status toggle: Unresolved → In Progress → Resolved
```

---

# ═══════════════════════════════════════════════
# PROMPT C: SERVIDORES + NOTIFICACIONES + CHAT IA
# ═══════════════════════════════════════════════

```text
Continue designing VicoGuard AI with the same Design System. Generate these screens:

### SCREEN C1: SERVER MONITORING — SERVER LIST
- Sidebar + top bar layout
- Page title: "Server Monitoring" + "Add Server" button (emerald)
- Grid of server cards (2 or 3 columns):
  - Each card:
    - Server name: "prod-server-01"
    - Status pill: 🟢 Online / 🟡 Degraded / 🔴 Down
    - Mini metrics: CPU gauge, RAM bar, Disk usage bar
    - Uptime: "99.97% (30d)"
    - Last event: "Brute force blocked — 2h ago"
    - "View Details →" link

### SCREEN C2: INDIVIDUAL SERVER DETAIL
- Header: Server name + IP address + Status pill + "Pause Monitoring" / "Remove" buttons
- **Tab 1: Overview**
  - Real-time charts (line graphs): CPU Usage (24h), Memory Usage (24h), Network I/O, Disk Usage
  - Health score: "Server Health: 87/100" (emerald gauge)
- **Tab 2: Live Logs**
  - Real-time log stream viewer (dark terminal style with JetBrains Mono):
    - Each log line color-coded: green for 200, amber for 4xx, red for 5xx
    - Filter controls: severity dropdown, search, auto-scroll toggle
    - "Export Logs" button
- **Tab 3: Attack Timeline**
  - Visual timeline (horizontal or vertical) showing security events:
    - 🔴 "14:23 — Brute Force Attack (50 login attempts from 185.234.72.15)"
    - 🟡 "14:25 — Wordpress Scanner Bot (1200 requests to /wp-admin — NOISE, filtered)"
    - 🔴 "14:26 — Database Connection Pool Exhausted"
    - 🟢 "14:28 — VicoGuard auto-recommended: Block IP via UFW"
    - Each event is expandable for details
- **Tab 4: Trigger Rules**
  - List of active trigger rules with toggle switches:
    - "Brute Force Detection" — Threshold: >50 failed logins/min — Action: Alert + Block IP — 🟢 Active
    - "DDoS / Traffic Spike" — Threshold: >10,000 req/min — Action: Alert + Rate Limit — 🟢 Active
    - "Server Down" — Condition: No response for 60s — Action: Alert All Channels — 🟢 Active
    - "Cryptojacking" — Condition: CPU >95% for >5min — Action: Alert — 🟡 Disabled
  - "Create Custom Trigger" button

### SCREEN C3: ATTACK IN PROGRESS — REAL-TIME ALERT MODAL
- Full-screen overlay modal with pulsing red border:
  - 🚨 Large animated alert icon
  - "ATTACK IN PROGRESS" headline (red, bold)
  - "Brute force attack detected on prod-server-01"
  - Real-time counter: "127 failed login attempts in the last 3 minutes"
  - Attacker info: IP, Country, ISP
  - AI Recommendation panel:
    - "VicoGuard AI recommends blocking this IP immediately. This will not affect your legitimate users."
    - Action buttons: "🛡️ Block IP Now" (red, prominent) + "⏸️ Monitor Only" (outline) + "❌ Dismiss"
  - "Notification sent to: Telegram ✓, Email ✓"

---

### SCREEN C4: NOTIFICATION CENTER (Full Page)
- Sidebar layout
- Page title: "Notifications"
- Tab bar: "All" | "Critical" | "Warnings" | "Info" | "Resolved"
- Filter: Date range + Asset + Channel sent
- Notification list (vertical cards):
  - Each notification card:
    - Left: Severity icon (colored circle)
    - Center: Title + Timestamp + Asset name + Short description
    - Right: Channel badges showing where it was sent (Telegram icon, Email icon, WhatsApp icon)
    - Status: "Read" / "Unread" (unread has emerald left border)
    - Expandable: Click to see full alert details + remediation
  - Batch actions: "Mark all as read", "Export"

### SCREEN C5: NOTIFICATION PREFERENCES / SETTINGS
- Sidebar layout
- Page title: "Notification Preferences"
- **Section 1: Connected Channels**
  - Telegram: Connected as @VicoGuardBot — Chat ID: 12345 — Status: 🟢 Active — "Test" button — "Disconnect" link
  - WhatsApp: Connected to +51 999 888 777 — Status: 🟢 Active — "Test" button — "Disconnect" link  
  - Email: alberto@vicoguard.ai — Status: 🟢 Active — "Test" button
  - "Add Channel" button (to add additional phones/emails)

- **Section 2: Alert Routing Rules (Matrix Table)**
  Table with checkboxes:
  | Event Type | Telegram | WhatsApp | Email | Push |
  | Critical Vulnerability | ✅ | ✅ | ✅ | ✅ |
  | High Severity | ✅ | ❌ | ✅ | ✅ |
  | Medium Severity | ✅ | ❌ | ❌ | ✅ |
  | Low / Info | ❌ | ❌ | ✅ (digest) | ❌ |
  | Server Down | ✅ | ✅ | ✅ | ✅ |
  | Attack Detected | ✅ | ✅ | ✅ | ✅ |
  | Scan Completed | ✅ | ❌ | ✅ | ❌ |
  | Weekly Report | ❌ | ❌ | ✅ | ❌ |

- **Section 3: Quiet Hours**
  - Toggle: "Enable quiet hours"
  - Time pickers: From 22:00 to 07:00
  - Exception: "Always alert for Critical severity, even during quiet hours" checkbox

- **Section 4: Digest Preferences**
  - "Daily Digest Email" toggle
  - "Weekly Security Report" toggle
  - Delivery time picker

### SCREEN C6: NOTIFICATION TEMPLATES PREVIEW
Show mockups of how notifications look on each channel:
- **Telegram Message Preview:** Dark chat bubble with VicoGuard bot avatar, Markdown-formatted alert with emoji severity indicators, code block for remediation, and action buttons (inline keyboard)
- **WhatsApp Message Preview:** WhatsApp-style green chat bubble with formatted text, bold headers, and emoji
- **Email Preview:** Clean HTML email template with VicoGuard header, security score visualization, vulnerability summary table, CTA button "View Full Report", and footer with unsubscribe link

---

### SCREEN C7: AI SECURITY ASSISTANT (Full Chat Interface)
- Sidebar layout, main area is the chat window
- Chat header: "VicoGuard AI Assistant" + status pill "🟢 Online" + context selector dropdown ("All Assets" / "tienda-lima.com" / "prod-server-01")
- Chat message area (scrollable):
  - Bot welcome message: "👋 Hi! I'm your security co-pilot. Ask me anything about your infrastructure. Try: 'Are there any active threats?' or 'Explain my last scan results simply.'"
  - User message: "What happened with my server in the last hour?"
  - Bot response: Formatted card with the correlated event summary, color-coded severity, and inline action buttons: [Block IP] [View Full Report] [Ignore]
  - User: "Explain the RLS vulnerability like I'm 5 years old"
  - Bot: Friendly analogy explanation with emoji
- Chat input area:
  - Text input: "Ask VicoGuard AI..."
  - Buttons: Attachment (upload logs), Voice input microphone, Send button
- Right sidebar (collapsible): "Context" panel showing current asset info, recent alerts, and quick command suggestions as clickable chips: "Run new scan", "Show server status", "Explain last alert", "Generate compliance report"
```

---

# ═══════════════════════════════════════════════
# PROMPT D: SETTINGS + BILLING + MSSP + BADGE + ESTADOS
# ═══════════════════════════════════════════════

```text
Continue designing VicoGuard AI. Same Design System. Generate these final screens:

### SCREEN D1: ACCOUNT SETTINGS
- Sidebar layout
- Page title: "Account Settings"
- **Section 1: Profile**
  - Avatar upload (circular, with "Change" overlay on hover)
  - Full Name input
  - Email input (with "Verified ✓" badge)
  - Company Name input
  - Timezone dropdown
  - Language dropdown (Español / English)
  - "Save Changes" button

- **Section 2: Security**
  - Change Password: Current password + New password + Confirm (with strength indicator)
  - Two-Factor Authentication: Toggle + QR code display for setup + Backup codes section
  - Active Sessions: Table showing device, IP, location, last active, with "Revoke" button per session

- **Section 3: API Keys**
  - "Your API Key" — Masked key (sk-vg-****xxxx) with "Copy" and "Regenerate" buttons
  - "Webhook URL" — Input field for receiving scan results via webhook
  - Usage stats: "API calls this month: 234 / 1,000"

- **Section 4: Danger Zone (Red bordered section)**
  - "Delete Account" — Warning text + "Delete my account and all data" button (red, requires confirmation modal)

### SCREEN D2: BILLING & SUBSCRIPTION PAGE
- Sidebar layout
- **Section 1: Current Plan**
  - Card showing: Plan name "Pro", Price "$39/month", Renewal date, Status "Active"
  - "Change Plan" button + "Cancel Subscription" link

- **Section 2: Plan Comparison**
  - 3-column plan cards (same as landing pricing but inside the app):
    - Free (current? or upgrade available)
    - Pro (highlighted if current)
    - Agency/MSSP
  - Feature comparison matrix table below with checkmarks

- **Section 3: Payment Method**
  - Current card: Visa ending in 4242, Exp 12/28 — "Update" button
  - "Add new payment method" link
  - Accepted: Visa, Mastercard, Amex icons

- **Section 4: Billing History**
  - Table: Date | Description | Amount | Status | Invoice
  - Each row has "Download PDF" link for invoice
  - "Jul 1, 2026 | Pro Plan — Monthly | $39.00 | ✅ Paid | Download"

### SCREEN D3: PAYMENT / CHECKOUT MODAL
- Modal overlay with frosted glass backdrop
- Left side: Order summary card
  - Plan: "Pro"
  - Price: "$39/month" (or "$374/year — Save 20%")
  - Features list
- Right side: Payment form
  - Card number input (with card type icon auto-detection)
  - Expiry + CVV row
  - Cardholder name
  - Country / ZIP
  - "Subscribe Now — $39/month" button (emerald, large)
  - Security badges: "🔒 Secured by Stripe" + "256-bit encryption"
  - "30-day money-back guarantee" text

---

### SCREEN D4: MSSP / AGENCY MULTI-TENANT DASHBOARD
- Different layout: Agency-branded top bar with their logo (white-label)
- **Overview panel:**
  - "Clients Overview" headline
  - KPI row: "Total Clients: 24" | "Critical Alerts: 3" | "Avg Score: 71/100" | "Scans Today: 18"
- **Client Grid (Sortable table):**
  | Client | Assets | Score | Status | Last Scan | Alerts | Actions |
  | TiendaLima S.A.C. | 2 | 38/100 🔴 | Critical | 1h ago | 3 | View / Scan |
  | FinApp Peru | 1 | 85/100 🟢 | Healthy | 3h ago | 0 | View / Scan |
  | RestaurantApp | 3 | 62/100 🟡 | Warning | 1d ago | 1 | View / Scan |
- "Add Client" button + "Generate Bulk Report" button + "Export All" button
- White-label settings link: "Customize branding →"

### SCREEN D5: WHITE-LABEL BRAND SETTINGS (Agency)
- Agency logo upload
- Primary color picker (replaces emerald with agency brand color)
- Custom domain input: "security.your-agency.com"
- Email sender name: "From: Security Team @ YourAgency"
- Preview pane showing how client dashboard looks with custom branding

---

### SCREEN D6: TRUST BADGE CONFIGURATOR
- Sidebar layout
- Page title: "Your Trust Badge"
- Left (60%): Live preview of the badge widget on a sample website footer (light and dark website mockup)
- Right (40%): Configuration panel:
  - Badge Style selector (3 options as visual thumbnails): "Dark", "Light", "Neon Glow"
  - Badge Size: "Small" / "Medium" / "Large" radio
  - Display: "Score + Text" / "Score Only" / "Shield Only"
  - Animation: Toggle "Enable pulse animation"
  - Current score shown: "92/100 — Verified Secure ✓"
  - "Copy Embed Code" button with the HTML snippet below in a monospaced code block:
    ```html
    <script src="https://badge.vicoguard.ai/v1/widget.js" data-id="vg_abc123"></script>
    ```
  - "Download as PNG" + "Download as SVG" buttons

---

### SCREEN D7: EMPTY STATES (Collection of 4 mini-screens)
Design beautiful, branded empty states for:
- **No Scans Yet:** Illustration/icon of a radar, "You haven't run any scans yet. Start your first audit to see results here." + "Run First Scan" CTA
- **No Servers Monitored:** Server icon, "Add your first server to start monitoring health and security 24/7." + "Add Server" CTA
- **No Notifications:** Bell icon, "All clear! No notifications yet. We'll alert you the moment something needs attention." 
- **No Vulnerabilities Found:** Shield with checkmark, "🎉 Congratulations! No vulnerabilities detected. Your app is looking great." (celebratory, emerald accent)

### SCREEN D8: ERROR PAGES
- **404 Page:** Centered on dark canvas. Large "404" in gradient text (emerald→violet). "This page doesn't exist, but your security threats do." Subtext + "Go to Dashboard" button. Subtle ASCII art or radar animation in background.
- **500 Page:** Large "500" in crimson. "Something went wrong on our end. We're fixing it." + "Try Again" button + "Report Issue" link.
- **Maintenance Page:** Shield icon with wrench. "We're upgrading VicoGuard AI. Be back in a few minutes." + Countdown timer + Status page link.

### SCREEN D9: MOBILE RESPONSIVE VIEWS (Show 3 phone-sized frames)
Show how key screens look on mobile (375px width):
- **Mobile Dashboard:** Stacked KPI cards, hamburger menu, simplified table as cards
- **Mobile Telegram Alert:** Phone frame showing a realistic Telegram conversation with the VicoGuard bot message (formatted alert with code block)
- **Mobile Scan Results:** Security Score gauge + scrollable vulnerability cards, bottom nav bar
```

---

## ✅ INVENTARIO TOTAL DE PANTALLAS (31 Interfaces)

| # | Pantalla | Prompt |
|---|----------|--------|
| 1 | Landing Page (Hero, Stats, Features, Pricing, Testimonials, Footer) | A |
| 2 | Registro / Sign Up | A |
| 3 | Login | A |
| 4 | Recuperar Contraseña | A |
| 5 | Verificación de Email | A |
| 6 | Autenticación 2FA | A |
| 7 | Onboarding — Paso 1: Tipo de Activo | B |
| 8 | Onboarding — Paso 2: URL / Repo | B |
| 9 | Onboarding — Paso 3: Conectar Canales | B |
| 10 | Onboarding — Paso 4: Primer Escaneo | B |
| 11 | Dashboard Principal (Command Center) | B |
| 12 | Historial de Escaneos | B |
| 13 | Detalle de Escaneo Individual | B |
| 14 | Lista de Servidores | C |
| 15 | Detalle de Servidor (Métricas + Logs + Ataques + Triggers) | C |
| 16 | Modal de Ataque en Progreso | C |
| 17 | Centro de Notificaciones | C |
| 18 | Preferencias de Notificación (Matriz de Canales) | C |
| 19 | Preview de Plantillas (Telegram, WhatsApp, Email) | C |
| 20 | Asistente IA (Chat Completo) | C |
| 21 | Configuración de Cuenta (Perfil, Seguridad, API Keys) | D |
| 22 | Billing & Suscripción | D |
| 23 | Modal de Pago / Checkout | D |
| 24 | Dashboard MSSP / Agencias (Multi-tenant) | D |
| 25 | White-Label Branding Settings | D |
| 26 | Configurador de Trust Badge | D |
| 27 | Estados Vacíos (4 variantes) | D |
| 28 | Página 404 | D |
| 29 | Página 500 | D |
| 30 | Página de Mantenimiento | D |
| 31 | Vistas Mobile (Dashboard, Telegram, Resultados) | D |
