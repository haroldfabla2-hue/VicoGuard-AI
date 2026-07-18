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

    if (result.scan_id) {
      $("export-btn").href = "/api/v1/scan/" + result.scan_id + "/export";
      $("report-export-container").style.display = "block";
    } else {
      $("report-export-container").style.display = "none";
    }

    const raw = result.scan_raw || {};
    $("kpi-critical").textContent = raw.critical ?? 0;
    $("kpi-critical-sub").textContent = (raw.total ?? 0) + " hallazgos en total";
    $("kpi-high").textContent = (raw.high || 0) + (raw.medium || 0);

    const findings = result.findings || [];
    const list = $("findings-list");
    if (!findings.length) { list.innerHTML = '<div class="empty">Sin hallazgos. ✓</div>'; return; }
    list.innerHTML = findings.map((f) => {
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
        "</div>"
      );
    }).join("");
  }

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
          loadStats(); loadEntities();
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
    // Carga estado previo del usuario (si ya escaneó antes en esta sesión)
    try {
      const latest = await (await api("/api/v1/scan/latest")).json();
      if (latest.result) renderResult(latest.result);
    } catch (_) {}
    loadStats(); loadEntities();
  })();
})();
