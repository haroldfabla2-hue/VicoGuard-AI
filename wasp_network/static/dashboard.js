// WASP Network dashboard — live view over Server-Sent Events.
// Uses the browser's native EventSource, no external library.
//
// Visual layer only (Obsidian Stealth design system, ported from
// VicoGuard-AI). The SSE wiring and data schema below are unchanged:
// GET /events streams "update" events whose payload is a JSON array of
// NodeSummary objects — { node_id, team_name, severity_counts:
// {critical,high,medium,low}, total_findings, denied_actions, last_updated }.

const grid = document.getElementById("nodes-grid");
const emptyState = document.getElementById("empty-state");

const connectionDot = document.getElementById("connection-dot");
const connectionText = document.getElementById("connection-text");
const nodeCountDot = document.getElementById("node-count-dot");
const nodeCountText = document.getElementById("node-count-text");

const SEVERITIES = ["critical", "high", "medium", "low"];

const SEVERITY_META = {
  critical: { label: "Critical", color: "#f43f5e" },
  high: { label: "High", color: "#ffb95f" },
  medium: { label: "Medium", color: "#e29100" },
  low: { label: "Low", color: "#4edea3" },
};

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function formatTimestamp(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);

  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.round(diffMs / 1000);

  if (diffSec < 0) return date.toLocaleTimeString();
  if (diffSec < 60) return `hace ${diffSec}s`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `hace ${diffMin}m`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `hace ${diffHr}h`;
  return date.toLocaleString();
}

function severityBorderClass(counts) {
  if ((counts.critical ?? 0) > 0) return "node-card--severity-critical";
  if ((counts.high ?? 0) > 0) return "node-card--severity-high";
  return "node-card--severity-clear";
}

function renderKpiTile(sev, count) {
  const meta = SEVERITY_META[sev];
  return `
    <div class="kpi-tile">
      <span class="kpi-tile__label">
        <span class="w-2 h-2 rounded-full" style="background:${meta.color}"></span>
        ${meta.label}
      </span>
      <span class="kpi-tile__value" style="color:${meta.color}">${count}</span>
    </div>
  `;
}

function renderNode(node) {
  const counts = node.severity_counts || {};
  const tiles = SEVERITIES.map((sev) => renderKpiTile(sev, counts[sev] ?? 0)).join("");
  const title = node.team_name ? escapeHtml(node.team_name) : escapeHtml(node.node_id);
  const deniedCount = node.denied_actions ?? 0;

  const deniedBadge = deniedCount > 0
    ? `<span class="denied-badge">⛔ ${deniedCount} acciones bloqueadas</span>`
    : "";

  return `
    <article class="node-card glass-panel ${severityBorderClass(counts)}">
      <div class="node-card__header">
        <h2 class="node-card__title">${title}</h2>
        <span class="node-card__timestamp">${formatTimestamp(node.last_updated)}</span>
      </div>

      <div class="kpi-grid">${tiles}</div>

      <div class="flex flex-wrap items-center justify-between gap-sm pt-sm border-t border-white/10 font-mono text-xs text-on-surface-variant">
        <span>Total hallazgos: <span class="text-on-surface font-semibold">${node.total_findings ?? 0}</span></span>
        ${deniedBadge}
      </div>
    </article>
  `;
}

function renderNodes(nodes) {
  const list = Array.isArray(nodes) ? nodes : [];

  updateNodeCountBadge(list.length);

  if (list.length === 0) {
    grid.innerHTML = "";
    emptyState.classList.remove("hidden");
    return;
  }

  emptyState.classList.add("hidden");

  const sorted = [...list].sort((a, b) =>
    (a.team_name || a.node_id).localeCompare(b.team_name || b.node_id)
  );

  grid.innerHTML = sorted.map(renderNode).join("");
}

function updateNodeCountBadge(count) {
  nodeCountText.textContent = `${count} nodo${count === 1 ? "" : "s"} activo${count === 1 ? "" : "s"}`;
  nodeCountDot.className = count > 0
    ? "w-2 h-2 rounded-full dot-glow-live"
    : "w-2 h-2 rounded-full bg-outline";
}

function setConnectionStatus(state) {
  // state: "connecting" | "live" | "error"
  if (state === "live") {
    connectionText.textContent = "En vivo";
    connectionDot.className = "w-2 h-2 rounded-full dot-glow-live";
  } else if (state === "error") {
    connectionText.textContent = "Reconectando…";
    connectionDot.className = "w-2 h-2 rounded-full dot-glow-error dot-pulse";
  } else {
    connectionText.textContent = "Conectando…";
    connectionDot.className = "w-2 h-2 rounded-full bg-outline dot-pulse";
  }
}

function connect() {
  const source = new EventSource("/events");

  source.addEventListener("open", () => {
    setConnectionStatus("live");
  });

  source.addEventListener("update", (event) => {
    try {
      const nodes = JSON.parse(event.data);
      renderNodes(nodes);
      fetchLedger();
    } catch (err) {
      console.error("WASP Network: failed to parse update", err);
    }
  });

  source.addEventListener("error", () => {
    setConnectionStatus("error");
  });
}

connect();

/* ------------------------------------------------------------------ */
/* Local node evidence: findings + SHA-256 hash chain                  */
/* Data comes from GET /ledger (this node's own audit ledger, local    */
/* only — never federated). Refreshed on every SSE update and polled   */
/* as a fallback so scans appear even without a publish.               */
/* ------------------------------------------------------------------ */

const findingsList = document.getElementById("findings-list");
const hashchainList = document.getElementById("hashchain-list");
const chainDot = document.getElementById("chain-dot");
const chainText = document.getElementById("chain-text");
const ledgerCountBadge = document.getElementById("ledger-count-badge");

let lastLedgerSignature = null;

const TYPE_META = {
  finding: { label: "finding", color: "#4edea3" },
  attack: { label: "attack", color: "#ffb95f" },
  consent: { label: "consent", color: "#d0bcff" },
  denied: { label: "denied", color: "#f43f5e" },
};

function shortHash(hash) {
  if (!hash) return "";
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

function renderChainBadge(valid) {
  if (valid) {
    chainText.textContent = "Cadena íntegra ✓";
    chainDot.className = "w-2 h-2 rounded-full dot-glow-live";
  } else {
    chainText.textContent = "Cadena ROTA ✗";
    chainDot.className = "w-2 h-2 rounded-full dot-glow-error dot-pulse";
  }
}

function renderFinding(entry) {
  const sev = entry.severity || "low";
  const meta = SEVERITY_META[sev] || SEVERITY_META.low;
  const location = entry.file ? `${escapeHtml(entry.file)}:${entry.line ?? "?"}` : "";
  const rule = entry.rule_id ? escapeHtml(entry.rule_id) : escapeHtml(entry.type || "");

  return `
    <article class="evidence-row glass-panel">
      <div class="flex items-center justify-between gap-sm">
        <span class="sev-chip" style="color:${meta.color};border-color:${meta.color}55;background:${meta.color}18">
          <span class="w-2 h-2 rounded-full" style="background:${meta.color}"></span>
          ${meta.label}
        </span>
        <span class="font-mono text-xs text-on-surface-variant">${formatTimestamp(entry.ts)}</span>
      </div>
      <p class="font-mono text-xs text-secondary overflow-wrap-anywhere">${rule}</p>
      <p class="text-sm text-on-surface leading-snug evidence-message" title="${escapeHtml(entry.message || "")}">${escapeHtml(entry.message || "")}</p>
      <p class="font-mono text-xs text-on-surface-variant overflow-wrap-anywhere">${location}</p>
    </article>
  `;
}

function renderHashEntry(entry) {
  const typeMeta = TYPE_META[entry.type] || { label: entry.type || "?", color: "#bbcabf" };

  return `
    <article class="evidence-row glass-panel">
      <div class="flex items-center justify-between gap-sm">
        <span class="font-mono text-xs font-semibold text-on-surface">#${entry.index}</span>
        <span class="type-chip" style="color:${typeMeta.color};border-color:${typeMeta.color}55;background:${typeMeta.color}18">${escapeHtml(typeMeta.label)}</span>
        <span class="font-mono text-xs text-on-surface-variant">${formatTimestamp(entry.ts)}</span>
      </div>
      <div class="hash-lines font-mono text-xs">
        <div class="flex gap-sm"><span class="text-on-surface-variant shrink-0">hash&nbsp;&nbsp;&nbsp;</span><span class="text-primary overflow-wrap-anywhere" title="${escapeHtml(entry.hash || "")}">${escapeHtml(shortHash(entry.hash))}</span></div>
        <div class="flex gap-sm"><span class="text-on-surface-variant shrink-0">prev&nbsp;&nbsp;&nbsp;</span><span class="text-on-surface-variant overflow-wrap-anywhere" title="${escapeHtml(entry.prev_hash || "")}">${escapeHtml(shortHash(entry.prev_hash))}</span></div>
      </div>
    </article>
  `;
}

function renderLedger(data) {
  renderChainBadge(data.chain_valid);
  ledgerCountBadge.textContent = `${data.total_entries} entrada${data.total_entries === 1 ? "" : "s"}`;

  const entries = Array.isArray(data.entries) ? data.entries : [];
  const findings = entries.filter((e) => e.type === "finding");

  findingsList.innerHTML = findings.length
    ? findings.map(renderFinding).join("")
    : `<p class="text-on-surface-variant text-sm">Sin hallazgos todavía — ejecutá un escaneo.</p>`;

  hashchainList.innerHTML = entries.length
    ? entries.map(renderHashEntry).join("")
    : `<p class="text-on-surface-variant text-sm">Ledger vacío.</p>`;
}

async function fetchLedger() {
  try {
    const res = await fetch("/ledger?limit=60");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Skip re-render when nothing changed (cheap signature: count + head hash).
    const head = data.entries && data.entries[0] ? data.entries[0].hash : "";
    const signature = `${data.total_entries}:${head}:${data.chain_valid}`;
    if (signature === lastLedgerSignature) return;
    lastLedgerSignature = signature;

    renderLedger(data);
  } catch (err) {
    console.error("WASP ledger: failed to fetch", err);
  }
}

fetchLedger();
setInterval(fetchLedger, 5000);
