/* VicoGuard AI — App dashboard (autenticado, aislado por usuario) */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const api = (path, opts) => fetch(path, Object.assign({ credentials: "include" }, opts));

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function initials(name, email) {
    const base = (name || email || "?").trim();
    const parts = base.split(/[\s@.]+/).filter(Boolean);
    return ((parts[0] || "?")[0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
  }
  function sevClass(s) { return String(s || "").toLowerCase(); }
  function scoreMeta(score) {
    const n = Number(score) || 0;
    if (n >= 80) return { label: "Riesgo bajo", color: "var(--accent)" };
    if (n >= 50) return { label: "Riesgo medio", color: "var(--high)" };
    return { label: "Riesgo crítico", color: "var(--critical)" };
  }

  // ---- auth gate ----
  async function requireAuth() {
    try {
      const res = await api("/api/v1/auth/me");
      if (!res.ok) throw new Error("401");
      const data = await res.json();
      const u = data.user;
      $("user-name").textContent = u.full_name || u.email.split("@")[0];
      $("user-company").textContent = u.company || u.email;
      $("avatar").textContent = initials(u.full_name, u.email);
      return u;
    } catch (_) {
      window.location.href = "/ui/login";
      return null;
    }
  }

  // ---- estado ----
  let currentScanId = null;

  // ---- terminal ----
  let lastRendered = 0;
  function resetTerminal() { $("terminal").innerHTML = ""; lastRendered = 0; }
  function renderEvents(events) {
    const term = $("terminal");
    if (!events || !events.length) return;
    if (events.length < lastRendered) { resetTerminal(); }
    for (let i = lastRendered; i < events.length; i++) {
      const ev = events[i];
      const row = document.createElement("div");
      row.className = "log " + String(ev.level || "INFO").toUpperCase();
      row.innerHTML =
        '<span class="t">' + escapeHtml(ev.ts || "--:--:--") + '</span>' +
        '<span class="a">' + escapeHtml(ev.agent || "SYS") + '</span>' +
        '<span class="m">' + escapeHtml(ev.message || "") + '</span>';
      term.appendChild(row);
    }
    lastRendered = events.length;
    term.scrollTop = term.scrollHeight;
  }

  // ---- results ----
  function renderResult(result) {
    if (!result) return;
    const score = Number(result.security_score) || 0;
    const meta = scoreMeta(score);
    $("score-num").textContent = isNaN(score) ? "—" : score;
    $("score-num").style.color = meta.color;
    const ring = $("ring-fg");
    ring.style.stroke = meta.color;
    ring.setAttribute("stroke-dashoffset", String(327 - (score / 100) * 327));
    const rl = $("risk-label");
    rl.textContent = meta.label;
    rl.className = "chip " + (score >= 80 ? "low" : score >= 50 ? "high" : "critical");
    $("scan-target").textContent = result.target_url || "";
    const srcMap = { llm: "GPT-4o", causal_cache: "Cache causal (<1s)", fallback: "heurístico" };
    $("scan-source").innerHTML = result.source
      ? '<span class="muted">Análisis:</span> ' + escapeHtml(srcMap[result.source] || result.source) : "";
    $("summary").textContent = result.summary || "Escaneo completado.";

    const raw = result.scan_raw || {};
    $("kpi-critical").textContent = raw.critical ?? 0;
    $("kpi-critical-sub").textContent = (raw.total ?? 0) + " hallazgos en total";
    $("kpi-high").textContent = (raw.high || 0) + (raw.medium || 0);

    currentScanId = result.scan_id || null;
    const findings = result.findings || [];
    const list = $("findings-list");
    const reportBtn = $("report-btn"), sendAllBtn = $("send-all-btn");
    if (reportBtn) reportBtn.disabled = !findings.length;
    if (sendAllBtn) sendAllBtn.disabled = !findings.length;
    if (!findings.length) { list.innerHTML = '<div class="empty">Sin hallazgos. ✓</div>'; return; }
    list.innerHTML = findings.map((f, i) => {
      const sev = (f.severity || "INFO").toUpperCase();
      const title = f.title_business || f.title_technical || f.title || "Hallazgo";
      const code = f.remediation_code || (Array.isArray(f.remediation_steps) ? f.remediation_steps.join("\n") : "");
      return (
        '<div class="finding">' +
          '<div class="row gap-12" style="justify-content:space-between; align-items:flex-start">' +
            '<div class="grow"><div class="title">' + escapeHtml(title) + "</div>" +
            (f.analogy ? '<div class="desc">💡 ' + escapeHtml(f.analogy) + "</div>" : "") +
            (f.impact ? '<div class="desc">' + escapeHtml(f.impact) + "</div>" : "") +
            "</div>" +
            '<span class="chip ' + sevClass(sev) + '">' + escapeHtml(sev) + "</span>" +
          "</div>" +
          (code ? "<pre>" + escapeHtml(code) + "</pre>" : "") +
          '<div class="finding-actions">' +
            '<button class="btn-xs" data-send="' + i + '">📤 Enviar remediación por Telegram</button>' +
          "</div>" +
        "</div>"
      );
    }).join("");
  }

  // ---- remediación (dashboard -> Telegram) ----
  async function sendRemediation(payload, btn) {
    const original = btn ? btn.innerHTML : "";
    if (btn) { btn.disabled = true; btn.textContent = "Enviando…"; }
    try {
      const res = await api("/api/v1/remediation/send", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({ scan_id: currentScanId }, payload)),
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(d.detail || "No se pudo enviar");
      if (btn) { btn.classList.add("sent"); btn.innerHTML = "✓ Enviado a Telegram"; }
      return true;
    } catch (ex) {
      if (btn) { btn.disabled = false; btn.innerHTML = original; }
      alert("Telegram: " + ex.message + (/Configura/.test(ex.message) ? "" : ""));
      return false;
    }
  }

  // ---- topología (grafo canónico) ----
  const SEV_COLOR = { CRITICAL: "#FF6B6B", HIGH: "#FF9145", MEDIUM: "#F4C24E", LOW: "#7FB0FF", "": "#94A3B8" };
  async function loadTopology() {
    try {
      const res = await api("/api/v1/brain/graph");
      if (!res.ok) return;
      const g = await res.json();
      renderTopology(g.nodes || [], g.edges || []);
    } catch (_) {}
  }
  function renderTopology(nodes, edges) {
    const wrap = $("topo-wrap");
    const vulns = nodes.filter((n) => n.type === "Vulnerability");
    const services = nodes.filter((n) => n.type === "Service");
    if (!vulns.length) return;
    $("topo-line").textContent = services.length + " servicio(s) · " + vulns.length + " vulnerabilidades";

    const W = 900, H = Math.max(360, 220 + vulns.length * 6);
    const cx = W / 2, cy = H / 2;
    const hub = services[0] || { id: "svc", label: (vulns[0] && vulns[0].host) || "target", host: "" };
    const R = Math.min(cx, cy) - 70;
    const pos = {};
    pos[hub.id] = { x: cx, y: cy };
    vulns.forEach((n, i) => {
      const a = (i / vulns.length) * Math.PI * 2 - Math.PI / 2;
      pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
    });

    let svg = '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="xMidYMid meet">';
    // edges: hub -> each vuln (AFFECTS) + any real edges present
    vulns.forEach((n) => {
      const p = pos[n.id];
      svg += '<line class="topo-edge" x1="' + cx + '" y1="' + cy + '" x2="' + p.x.toFixed(1) + '" y2="' + p.y.toFixed(1) + '"/>';
    });
    // hub node
    svg += '<circle cx="' + cx + '" cy="' + cy + '" r="34" fill="#0E1A33" stroke="#4C86FF" stroke-width="2"/>';
    svg += '<text class="topo-hub-label" text-anchor="middle" x="' + cx + '" y="' + (cy + 4) + '">' + esc(hub.host || hub.label || "target") + "</text>";
    // vuln nodes
    vulns.forEach((n) => {
      const p = pos[n.id];
      const color = SEV_COLOR[n.severity] || SEV_COLOR[""];
      const r = 9 + Math.min(6, (n.evidence_count || 1) - 1) * 1.5;
      const tip = (n.component || n.label || "") + " · " + (n.cwe || "") + " · ev#" + (n.evidence_count || 1);
      svg += '<circle class="topo-vuln" data-tip="' + esc(tip) + '" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) +
             '" r="' + r.toFixed(1) + '" fill="' + color + '22" stroke="' + color + '" stroke-width="2"/>';
      const lx = p.x, ly = p.y > cy ? p.y + r + 12 : p.y - r - 7;
      svg += '<text class="topo-node-label" text-anchor="middle" x="' + lx.toFixed(1) + '" y="' + ly.toFixed(1) + '">' +
             esc((n.component || n.key || "").slice(0, 22)) + "</text>";
    });
    svg += "</svg>";
    wrap.innerHTML = svg;

    // tooltip
    const tip = document.createElement("div"); tip.className = "topo-tip"; wrap.appendChild(tip);
    wrap.querySelectorAll(".topo-vuln").forEach((el) => {
      el.addEventListener("mousemove", (e) => {
        const rct = wrap.getBoundingClientRect();
        tip.textContent = el.getAttribute("data-tip");
        tip.style.left = (e.clientX - rct.left + 12) + "px";
        tip.style.top = (e.clientY - rct.top + 12) + "px";
        tip.style.opacity = "1";
      });
      el.addEventListener("mouseleave", () => { tip.style.opacity = "0"; });
    });
  }
  function esc(s) { return escapeHtml(s); }

  // ---- stats + entities ----
  async function loadStats() {
    try {
      const res = await api("/api/v1/brain/stats");
      if (!res.ok) return;
      const d = await res.json();
      const b = d.brain || {}, c = d.canonical || {};
      $("kpi-brain").textContent = b.total_memories ?? 0;
      $("kpi-canonical").textContent = c.unique_entities ?? 0;
      const merges = c.merges ?? 0;
      $("kpi-canonical-sub").textContent = merges > 0
        ? merges + " evidencias fusionadas · 0 duplicados"
        : (c.unique_vulnerabilities ?? 0) + " vulns · sin duplicados";
      $("dedup-line").textContent =
        (c.unique_entities ?? 0) + " nodos · " + (c.evidences ?? 0) + " evidencias · " +
        (c.redundant_nodes_avoided ?? 0) + " duplicados evitados";
    } catch (_) {}
  }
  async function loadEntities() {
    try {
      const res = await api("/api/v1/brain/entities?limit=40");
      if (!res.ok) return;
      const d = await res.json();
      const ents = (d.entities || []).filter((e) => e.entity_type === "Vulnerability");
      const list = $("entities-list");
      if (!ents.length) return;
      list.innerHTML = ents.map((e) =>
        '<div class="finding"><div class="row gap-12" style="justify-content:space-between">' +
          '<div class="grow"><div class="title mono small">' + escapeHtml(e.canonical_id) + "</div>" +
          '<div class="desc mono">' + escapeHtml(e.normalized_key) + "</div></div>" +
          '<div class="stack" style="align-items:flex-end">' +
            '<span class="chip">ev #' + (e.evidence_count ?? 0) + "</span>" +
            '<span class="small muted" style="margin-top:4px">v' + (e.version ?? 1) + "</span>" +
          "</div>" +
        "</div></div>"
      ).join("");
    } catch (_) {}
  }

  // ---- scan flow ----
  let polling = null;
  async function runScan(url, notify) {
    if (polling) clearInterval(polling);
    resetTerminal();
    $("scan-btn").disabled = true; $("scan-btn").textContent = "Escaneando…";
    $("scan-status").textContent = "en curso"; $("scan-status").className = "chip high";
    try {
      const res = await api("/api/v1/scan/start", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: url, notify: !!notify, channels: ["telegram"] }),
      });
      const started = await res.json();
      if (!res.ok) throw new Error(started.detail || "No se pudo iniciar el escaneo");
      const sid = started.scan_id;
      polling = setInterval(async () => {
        const job = await (await api("/api/v1/scan/" + sid)).json();
        renderEvents(job.events || []);
        if (job.status === "completed" || job.status === "failed") {
          clearInterval(polling); polling = null;
          $("scan-btn").disabled = false; $("scan-btn").textContent = "Escanear ahora";
          $("scan-status").textContent = job.status === "completed" ? "completado" : "fallido";
          $("scan-status").className = "chip " + (job.status === "completed" ? "low" : "critical");
          if (job.result) renderResult(job.result);
          loadStats(); loadEntities(); loadTopology();
        }
      }, 900);
    } catch (ex) {
      $("scan-btn").disabled = false; $("scan-btn").textContent = "Escanear ahora";
      $("scan-status").textContent = "error"; $("scan-status").className = "chip critical";
      const term = $("terminal");
      const row = document.createElement("div");
      row.className = "log ALERT";
      row.innerHTML = '<span class="m">&gt; ' + escapeHtml(ex.message) + "</span>";
      term.appendChild(row);
    }
  }

  // ---- business profile, history & saas plan ----
  async function loadBusinessProfile() {
    try {
      const res = await api("/api/v1/business-profile");
      if (!res.ok) return;
      const data = await res.json();
      if (data.profile) {
        $("prof-sector-badge").textContent = (data.profile.sector || "general").toUpperCase();
        const summary = data.risk_summary || {};
        const chip = $("prof-posture-chip");
        chip.textContent = "Postura: " + (summary.risk_posture || "media").toUpperCase();
        chip.className = "chip " + (summary.risk_posture === "alto" ? "critical" : summary.risk_posture === "bajo" ? "low" : "high");
        $("prof-narrative").textContent = summary.narrative || data.profile.description || "";
        const crownWrap = $("prof-crown-list");
        crownWrap.innerHTML = "";
        const jewels = summary.crown_jewels || data.profile.data || [];
        if (jewels.length) {
          jewels.forEach(j => {
            const span = document.createElement("span");
            span.className = "chip small";
            span.textContent = j;
            crownWrap.appendChild(span);
          });
        } else {
          crownWrap.innerHTML = '<span class="chip small">Datos generales</span>';
        }
      }
    } catch (e) {
      console.warn("Error cargando perfil de negocio:", e);
    }
  }

  async function loadScanHistory() {
    try {
      const res = await api("/api/v1/scans/history");
      if (!res.ok) return;
      const data = await res.json();
      const list = $("history-list");
      const stats = $("history-stats");
      if (stats) stats.textContent = (data.total_scans || 0) + " escaneos · Promedio: " + (data.avg_score || 0) + "/100";
      if (!data.history || !data.history.length) {
        list.innerHTML = '<div class="empty">Ejecuta tu primer escaneo para habilitar el seguimiento de tendencias.</div>';
        return;
      }
      list.innerHTML = "";
      data.history.forEach(item => {
        const div = document.createElement("div");
        div.className = "row gap-12 align-center justify-between";
        div.style.padding = "10px 14px";
        div.style.borderBottom = "1px solid var(--line, #232d3f)";
        const scoreCol = item.score >= 80 ? "var(--accent)" : item.score >= 50 ? "var(--high)" : "var(--critical)";
        div.innerHTML = `
          <div class="stack gap-4">
            <strong style="font-size:14px">${escapeHtml(item.target)}</strong>
            <span class="small muted">${escapeHtml(item.created_at)}</span>
          </div>
          <div class="row gap-12 align-center">
            <span class="chip small">${item.findings_count} hallazgos</span>
            <strong style="color:${scoreCol}; font-size:16px">${item.score}/100</strong>
          </div>
        `;
        list.appendChild(div);
      });
    } catch (e) {
      console.warn("Error cargando historial de escaneos:", e);
    }
  }

  async function loadSaaSPlan() {
    try {
      const res = await api("/api/v1/billing/plan");
      if (!res.ok) return;
      const data = await res.json();
      $("plan-tier-chip").textContent = "Plan " + data.plan;
      $("plan-usage-text").textContent = data.scans_used + " / " + (data.scans_limit >= 999 ? "∞" : data.scans_limit);
      const pct = Math.min(100, Math.round((data.scans_used / (data.scans_limit || 1)) * 100));
      $("plan-bar").style.width = pct + "%";
    } catch (e) {
      console.warn("Error cargando plan SaaS:", e);
    }
  }

  // ---- init ----
  (async function init() {
    const user = await requireAuth();
    if (!user) return;
    $("logout").addEventListener("click", async () => {
      await api("/api/v1/auth/logout", { method: "POST" });
      window.location.href = "/ui/login";
    });
    $("use-demo").addEventListener("click", () => {
      $("url").value = window.location.origin + "/demo/vulnerable";
    });
    $("scan-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const url = $("url").value.trim();
      if (url) runScan(url, $("notify").checked);
    });

    // Reporte
    const reportBtn = $("report-btn");
    if (reportBtn) reportBtn.addEventListener("click", () => {
      const url = currentScanId ? "/api/v1/scan/" + currentScanId + "/report" : "/api/v1/report/latest";
      window.open(url, "_blank");
    });

    // Enviar todas las remediaciones
    const sendAllBtn = $("send-all-btn");
    if (sendAllBtn) sendAllBtn.addEventListener("click", () => sendRemediation({ send_all: true }, sendAllBtn));

    // Enviar remediación de un hallazgo (delegación)
    $("findings-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-send]");
      if (b) sendRemediation({ finding_index: Number(b.getAttribute("data-send")) }, b);
    });

    // Modal Cuestionario Perfil de Negocio
    const openModalBtn = $("open-profile-btn");
    const closeModalBtn = $("close-profile-btn");
    const profileModal = $("profile-modal");
    if (openModalBtn) openModalBtn.addEventListener("click", () => { profileModal.style.display = "flex"; });
    if (closeModalBtn) closeModalBtn.addEventListener("click", () => { profileModal.style.display = "none"; });

    const profileForm = $("profile-form");
    if (profileForm) {
      profileForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const sector = $("pq-sector").value;
        const description = $("pq-desc").value.trim();
        const dataArr = Array.from(document.querySelectorAll('input[name="pq-data"]:checked')).map(cb => cb.value);
        const stackArr = Array.from(document.querySelectorAll('input[name="pq-stack"]:checked')).map(cb => cb.value);
        const concern = $("pq-concern").value;
        
        const submitBtn = $("save-profile-submit");
        submitBtn.disabled = true; submitBtn.textContent = "Sintetizando modelo de riesgo...";
        try {
          const res = await api("/api/v1/business-profile", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sector, description, data: dataArr, stack: stackArr, concern }),
          });
          if (!res.ok) throw new Error("Error al guardar perfil");
          profileModal.style.display = "none";
          loadBusinessProfile();
        } catch (ex) {
          alert("Error: " + ex.message);
        } finally {
          submitBtn.disabled = false; submitBtn.textContent = "Guardar Contexto";
        }
      });
    }

    // Botones de cambio de Plan SaaS
    const upgradePro = $("upgrade-pro-btn");
    const upgradeEnt = $("upgrade-ent-btn");
    if (upgradePro) upgradePro.addEventListener("click", async () => {
      await api("/api/v1/billing/plan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ plan: "Pro" }) });
      loadSaaSPlan();
    });
    if (upgradeEnt) upgradeEnt.addEventListener("click", async () => {
      await api("/api/v1/billing/plan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ plan: "Enterprise" }) });
      loadSaaSPlan();
    });

    // Carga estado previo del usuario
    try {
      const latest = await (await api("/api/v1/scan/latest")).json();
      if (latest.result) renderResult(latest.result);
    } catch (_) {}
    loadStats(); loadEntities(); loadTopology();
    loadBusinessProfile(); loadScanHistory(); loadSaaSPlan();
  })();
})();

