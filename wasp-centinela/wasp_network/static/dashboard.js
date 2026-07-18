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
    } catch (err) {
      console.error("WASP Network: failed to parse update", err);
    }
  });

  source.addEventListener("error", () => {
    setConnectionStatus("error");
  });
}

connect();
