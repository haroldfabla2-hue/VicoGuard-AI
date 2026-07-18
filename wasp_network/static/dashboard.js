// WASP Network dashboard — live view over Server-Sent Events.
// Uses the browser's native EventSource, no external library.

const grid = document.getElementById("nodes-grid");
const emptyState = document.getElementById("empty-state");
const statusEl = document.getElementById("connection-status");

const SEVERITIES = ["critical", "high", "medium", "low"];

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch (err) {
    return iso;
  }
}

function renderNode(node) {
  const counts = node.severity_counts || {};
  const pills = SEVERITIES.map((sev) => `
    <div class="severity-pill ${sev}">
      <span class="count">${counts[sev] ?? 0}</span>
      <span class="label">${sev}</span>
    </div>
  `).join("");

  const title = node.team_name ? escapeHtml(node.team_name) : escapeHtml(node.node_id);

  return `
    <article class="node-card">
      <div class="node-card__header">
        <h2 class="node-card__name">${title}</h2>
        <span class="node-card__id">${escapeHtml(node.node_id)}</span>
      </div>
      <div class="severity-row">${pills}</div>
      <div class="node-card__footer">
        <span>Total: <span class="node-card__total">${node.total_findings ?? 0}</span></span>
        <span>Bloqueadas: <span class="node-card__denied">${node.denied_actions ?? 0}</span></span>
        <span>${formatTimestamp(node.last_updated)}</span>
      </div>
    </article>
  `;
}

function renderNodes(nodes) {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    grid.innerHTML = "";
    grid.appendChild(emptyState);
    return;
  }

  const sorted = [...nodes].sort((a, b) =>
    (a.team_name || a.node_id).localeCompare(b.team_name || b.node_id)
  );

  grid.innerHTML = sorted.map(renderNode).join("");
}

function setStatus(text, className) {
  statusEl.textContent = text;
  statusEl.className = "status" + (className ? ` ${className}` : "");
}

function connect() {
  const source = new EventSource("/events");

  source.addEventListener("open", () => {
    setStatus("En vivo", "live");
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
    setStatus("Reconectando…", "error");
  });
}

connect();
