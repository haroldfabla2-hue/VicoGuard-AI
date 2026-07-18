/**
 * VicoGuard AI — Cliente API compartido para las pantallas HTML
 * Conecta ui_stitch ↔ FastAPI (localhost:8000)
 */
(function (global) {
  const DEFAULT_API = "http://localhost:8000";

  function getApiBase() {
    // Si la UI se sirve desde FastAPI, usar el mismo origen
    if (global.location && global.location.port === "8000") {
      return global.location.origin;
    }
    return global.localStorage.getItem("vg_api_base") || DEFAULT_API;
  }

  const API = {
    base() {
      return getApiBase();
    },

    async health() {
      const res = await fetch(`${getApiBase()}/api/v1/health`);
      if (!res.ok) throw new Error(`Health ${res.status}`);
      return res.json();
    },

    async startScan(repoUrl, notify = true) {
      const res = await fetch(`${getApiBase()}/api/v1/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: repoUrl,
          notify,
          channels: ["telegram"],
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Scan start failed (${res.status})`);
      }
      return res.json();
    },

    async getScan(scanId) {
      const res = await fetch(`${getApiBase()}/api/v1/scan/${scanId}`);
      if (!res.ok) throw new Error(`Scan status ${res.status}`);
      return res.json();
    },

    async getLatestScan() {
      const res = await fetch(`${getApiBase()}/api/v1/scan/latest`);
      if (!res.ok) throw new Error(`Latest scan ${res.status}`);
      return res.json();
    },

    async getBrainStats() {
      const res = await fetch(`${getApiBase()}/api/v1/brain/stats`);
      if (!res.ok) throw new Error(`Brain stats ${res.status}`);
      return res.json();
    },

    async submitFeedback(fingerprint, success) {
      const res = await fetch(`${getApiBase()}/api/v1/brain/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threat_fingerprint: fingerprint,
          success,
        }),
      });
      if (!res.ok) throw new Error(`Feedback ${res.status}`);
      return res.json();
    },

    /**
     * Polling del scan async hasta completed/failed.
     * onEvent(job) se llama en cada tick con el estado completo.
     */
    async pollScan(scanId, { onEvent, intervalMs = 800, timeoutMs = 120000 } = {}) {
      const started = Date.now();
      let lastEventCount = 0;

      while (Date.now() - started < timeoutMs) {
        const job = await this.getScan(scanId);
        if (onEvent && job.events && job.events.length > lastEventCount) {
          onEvent(job, job.events.slice(lastEventCount));
          lastEventCount = job.events.length;
        } else if (onEvent) {
          onEvent(job, []);
        }

        if (job.status === "completed" || job.status === "failed") {
          if (job.result) {
            try {
              global.localStorage.setItem("vg_latest_scan", JSON.stringify(job.result));
              global.localStorage.setItem("vg_latest_scan_id", scanId);
            } catch (_) {}
          }
          return job;
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }
      throw new Error("Timeout esperando resultado del scan");
    },

    scoreLabel(score) {
      const n = Number(score) || 0;
      if (n >= 80) return { text: "SECURE", color: "#4edea3", risk: "Low Risk" };
      if (n >= 50) return { text: "AT RISK", color: "#ffb95f", risk: "Medium Risk" };
      return { text: "CRITICAL RISK", color: "#f43f5e", risk: "Critical Risk" };
    },

    severityColor(sev) {
      const map = {
        CRITICAL: "#f43f5e",
        HIGH: "#ffb95f",
        MEDIUM: "#fbbf24",
        LOW: "#60a5fa",
        INFO: "#94a3b8",
      };
      return map[String(sev || "").toUpperCase()] || "#94a3b8";
    },
  };

  global.VicoGuard = API;
})(typeof window !== "undefined" ? window : globalThis);
