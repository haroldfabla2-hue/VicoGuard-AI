/* VicoGuard AI — Configuración de cuenta (perfil + notificaciones) */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const api = (path, opts) => fetch(path, Object.assign({ credentials: "include" }, opts));

  function initials(name, email) {
    const base = (name || email || "?").trim();
    const parts = base.split(/[\s@.]+/).filter(Boolean);
    return ((parts[0] || "?")[0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
  }

  async function loadProfile() {
    const res = await api("/api/v1/auth/me");
    if (!res.ok) { window.location.href = "/ui/login"; return null; }
    const u = (await res.json()).user;
    $("user-name").textContent = u.full_name || u.email.split("@")[0];
    $("user-company").textContent = u.company || u.email;
    $("avatar").textContent = initials(u.full_name, u.email);
    $("pf-name").textContent = u.full_name || "—";
    $("pf-company").textContent = u.company || "—";
    $("pf-email").textContent = u.email;
    return u;
  }

  async function loadSettings() {
    try {
      const res = await api("/api/v1/settings");
      if (!res.ok) return;
      const d = await res.json();
      $("settings-chat").value = d.telegram_chat_id || "";
      const tokenField = $("settings-token");
      const state = $("tg-state");
      if (d.telegram_bot_token) {
        tokenField.value = "";
        tokenField.placeholder = "•••• token configurado (" + d.telegram_bot_token + ") — escribe uno nuevo para cambiarlo";
        state.textContent = "configurado";
        state.className = "chip secure";
      } else {
        tokenField.placeholder = "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ";
        state.textContent = "no configurado";
        state.className = "chip";
      }
    } catch (_) {}
  }

  function setStatus(msg, color) {
    const st = $("settings-status");
    st.textContent = msg;
    st.style.color = color || "var(--text-dim)";
  }

  (async function init() {
    const user = await loadProfile();
    if (!user) return;
    await loadSettings();

    $("logout").addEventListener("click", async () => {
      await api("/api/v1/auth/logout", { method: "POST" });
      window.location.href = "/ui/login";
    });

    $("settings-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      setStatus("Guardando…", "var(--blue)");
      const body = { telegram_chat_id: $("settings-chat").value.trim() };
      const tok = $("settings-token").value.trim();
      if (tok) body.telegram_bot_token = tok; // solo si escribió uno nuevo
      try {
        const res = await api("/api/v1/settings", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(d.detail || "Error al guardar");
        setStatus("✓ Configuración guardada.", "var(--secure)");
        await loadSettings();
      } catch (ex) { setStatus("❌ " + ex.message, "var(--critical)"); }
    });

    $("test-telegram-btn").addEventListener("click", async () => {
      const btn = $("test-telegram-btn");
      btn.disabled = true; setStatus("Enviando prueba…", "var(--blue)");
      try {
        const res = await api("/api/v1/settings/test", { method: "POST" });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(d.detail || "Error");
        setStatus("✓ Prueba enviada. Revisa tu Telegram.", "var(--secure)");
      } catch (ex) { setStatus("❌ " + ex.message, "var(--critical)"); }
      finally { btn.disabled = false; }
    });

    $("clear-token-btn").addEventListener("click", async () => {
      if (!confirm("¿Borrar el bot token guardado? Dejarás de recibir alertas hasta configurar otro.")) return;
      setStatus("Borrando…", "var(--blue)");
      try {
        const res = await api("/api/v1/settings", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ telegram_bot_token: "__clear__" }),
        });
        if (!res.ok) throw new Error("Error");
        setStatus("✓ Token borrado.", "var(--secure)");
        $("settings-token").value = "";
        await loadSettings();
      } catch (ex) { setStatus("❌ " + ex.message, "var(--critical)"); }
    });
  })();
})();
