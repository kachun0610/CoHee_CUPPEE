(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  let scannedMember = null;
  let menuItems = [];

  async function api(url, options = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || res.statusText || "Request failed");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function setMsg(el, text, kind = "") {
    if (!el) return;
    el.textContent = text || "";
    el.classList.remove("is-ok", "is-error");
    if (kind) el.classList.add(kind);
  }

  function setOrb(orb, state) {
    if (!orb) return;
    orb.classList.remove("is-scanning", "is-valid", "is-expired", "is-suspended", "is-error");
    if (state) orb.classList.add(`is-${state}`);
  }

  // ---- Tabs ----
  function showTab(name) {
    $$(".tab").forEach((tab) => {
      const on = tab.dataset.tab === name;
      tab.classList.toggle("is-active", on);
      tab.setAttribute("aria-selected", on ? "true" : "false");
    });
    $$(".panel").forEach((panel) => {
      const on = panel.id === `panel-${name}`;
      panel.classList.toggle("is-active", on);
      panel.hidden = !on;
    });
    if (name === "admin") refreshAdminSession();
    if (name === "db") refreshDbSession();
  }

  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  });

  // ---- Reader status ----
  async function refreshReader() {
    const el = $("#reader-status");
    try {
      const data = await api("/api/reader");
      el.classList.remove("is-ok", "is-warn", "is-bad");
      if (!data.ok) {
        el.classList.add("is-bad");
        el.textContent = data.error || "Reader unavailable";
        return;
      }
      if (data.mode === "simulation") {
        el.classList.add("is-warn");
        el.textContent = `Demo mode · ${data.reader}`;
      } else {
        el.classList.add("is-ok");
        el.textContent = `Reader ready · ${data.reader}`;
      }
    } catch (e) {
      el.classList.add("is-bad");
      el.textContent = e.message;
    }
  }

  // ---- Check / Scan ----
  function fillMenuSelect() {
    const sel = $("#purchase-item");
    if (!sel) return;
    const current = sel.value;
    sel.innerHTML =
      '<option value="">Select an item…</option>' +
      menuItems
        .map(
          (item) =>
            `<option value="${escapeHtml(item.id)}" data-price="${item.price}">${escapeHtml(item.name)} — HKD ${item.price}</option>`
        )
        .join("");
    if (current && menuItems.some((i) => i.id === current)) sel.value = current;
    updatePurchasePrice();
  }

  function updatePurchasePrice() {
    const sel = $("#purchase-item");
    const line = $("#purchase-price");
    const opt = sel?.selectedOptions?.[0];
    const price = opt?.dataset?.price;
    if (!price) {
      line.hidden = true;
      return;
    }
    line.hidden = false;
    line.innerHTML = `Price · HKD <strong>${escapeHtml(price)}</strong>`;
  }

  function purchaseLabel(items) {
    if (!items) return "";
    if (typeof items === "object" && items.name) return items.name;
    if (typeof items === "object" && items.note) return items.note;
    if (Array.isArray(items)) return items.map((i) => i.name || i).join(", ");
    return String(items);
  }

  function renderPurchases(list) {
    const wrap = $("#purchase-list");
    const ul = $("#purchase-list-ul");
    if (!list || !list.length) {
      wrap.hidden = true;
      ul.innerHTML = "";
      return;
    }
    wrap.hidden = false;
    ul.innerHTML = list
      .map((p) => {
        return `<li>
          <strong>${escapeHtml(purchaseLabel(p.items))}</strong>
          <span>HKD ${Number(p.amount).toFixed(0)} · +${p.points_earned} pts · ${escapeHtml(p.purchased_at)}</span>
        </li>`;
      })
      .join("");
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showScanned(data) {
    const member = data.member;
    const avail = data.availability || {};
    scannedMember = member;

    const stateEl = $("#check-state");
    stateEl.textContent = avail.label || "Scanned";
    stateEl.className = "result-state";
    if (avail.state) stateEl.classList.add(`is-${avail.state}`);

    $("#check-detail").textContent =
      avail.state === "valid"
        ? "Membership is active"
        : avail.state === "expired"
          ? "Membership has expired"
          : avail.state === "suspended"
            ? "Membership is suspended"
            : "";

    $("#check-meta").hidden = false;
    $("#check-uid").textContent = data.uid ? `UID  ${data.uid}` : "";
    $("#check-name").textContent = member.name || "";
    $("#check-id").textContent = `ID  ${member.member_id}`;
    $("#check-points").textContent = `${member.loyalty_points} loyalty points · ${member.tier || ""}`;
    $("#check-dates").textContent = [
      member.start_date ? `Start ${member.start_date}` : "",
      member.end_date ? `End ${member.end_date}` : "",
      member.status || "",
    ]
      .filter(Boolean)
      .join("  ·  ");

    setOrb($("#check-orb"), avail.state || "valid");
    $("#purchase-form").hidden = false;
    renderPurchases(data.purchases || []);
    setMsg($("#purchase-msg"), "");
  }

  function clearCheckResult(message, detail) {
    scannedMember = null;
    const stateEl = $("#check-state");
    stateEl.textContent = message;
    stateEl.className = "result-state";
    $("#check-detail").textContent = detail || "";
    $("#check-meta").hidden = true;
    $("#purchase-form").hidden = true;
    $("#purchase-list").hidden = true;
  }

  $("#btn-scan").addEventListener("click", async () => {
    const btn = $("#btn-scan");
    btn.disabled = true;
    btn.textContent = "Scanning…";
    setOrb($("#check-orb"), "scanning");
    clearCheckResult("Scanning…", "Hold the cup steady on the reader");

    try {
      const data = await api("/api/check/scan", { method: "POST", body: "{}" });
      showScanned(data);
    } catch (e) {
      clearCheckResult("Error", e.message);
      $("#check-state").classList.add("is-error");
      setOrb($("#check-orb"), "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Scan membership";
    }
  });

  $("#purchase-item")?.addEventListener("change", updatePurchasePrice);

  $("#purchase-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!scannedMember) return;

    const btn = $("#btn-purchase");
    const menuItemId = $("#purchase-item").value;
    const updateCard = $("#purchase-update-card").checked;

    if (!menuItemId) {
      setMsg($("#purchase-msg"), "Select a menu item", "is-error");
      return;
    }

    btn.disabled = true;
    setMsg($("#purchase-msg"), "Saving…");

    try {
      const data = await api("/api/check/purchase", {
        method: "POST",
        body: JSON.stringify({
          member_id: scannedMember.member_id,
          name: scannedMember.name,
          loyalty_points: scannedMember.loyalty_points,
          start_date: scannedMember.start_date,
          end_date: scannedMember.end_date,
          status: scannedMember.status,
          tier: scannedMember.tier,
          menu_item_id: menuItemId,
          update_card: updateCard,
        }),
      });

      scannedMember.loyalty_points = data.loyalty_points;
      $("#check-points").textContent = `${data.loyalty_points} loyalty points · ${scannedMember.tier || ""}`;

      let msg = `Saved · +${data.points_earned} pts (now ${data.loyalty_points})`;
      if (updateCard && data.card_error) msg += ` · card not updated: ${data.card_error}`;
      else if (updateCard && data.card_updated) msg += " · card updated";

      setMsg($("#purchase-msg"), msg, data.card_error ? "is-error" : "is-ok");
      $("#purchase-item").value = "";
      updatePurchasePrice();
      prependPurchase(data.purchase);
    } catch (e) {
      setMsg($("#purchase-msg"), e.message, "is-error");
    } finally {
      btn.disabled = false;
    }
  });

  function prependPurchase(p) {
    const wrap = $("#purchase-list");
    const ul = $("#purchase-list-ul");
    wrap.hidden = false;
    const li = document.createElement("li");
    li.innerHTML = `<strong>${escapeHtml(purchaseLabel(p.items))}</strong>
      <span>HKD ${Number(p.amount).toFixed(0)} · +${p.points_earned} pts · ${escapeHtml(p.purchased_at)}</span>`;
    ul.prepend(li);
  }

  // ---- Admin ----
  async function refreshAdminSession() {
    try {
      const data = await api("/api/admin/session");
      setAdminUnlocked(!!data.authenticated);
    } catch {
      setAdminUnlocked(false);
    }
  }

  function setAdminUnlocked(unlocked) {
    $("#admin-gate").hidden = unlocked;
    $("#admin-workspace").hidden = !unlocked;
  }

  $("#btn-admin-login").addEventListener("click", async () => {
    const password = $("#admin-password").value;
    setMsg($("#admin-login-msg"), "Checking…");
    try {
      await api("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      $("#admin-password").value = "";
      setMsg($("#admin-login-msg"), "");
      setAdminUnlocked(true);
    } catch (e) {
      setMsg($("#admin-login-msg"), e.message || "Incorrect password", "is-error");
    }
  });

  $("#admin-password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-admin-login").click();
  });

  $("#btn-admin-logout").addEventListener("click", async () => {
    await api("/api/admin/logout", { method: "POST", body: "{}" });
    setAdminUnlocked(false);
  });

  $("#btn-gen-id").addEventListener("click", async () => {
    try {
      const data = await api("/api/admin/generate-id", { method: "POST", body: "{}" });
      $("#admin-id").value = data.member_id;
    } catch (e) {
      setMsg($("#admin-msg"), e.message, "is-error");
    }
  });

  function fillAdminForm(member) {
    $("#admin-name").value = member.name || "";
    $("#admin-id").value = member.member_id || "";
    $("#admin-points").value = member.loyalty_points ?? 0;
    $("#admin-start").value = member.start_date || "";
    $("#admin-end").value = member.end_date || "";
    if (member.status) $("#admin-status").value = member.status;
    if (member.tier) $("#admin-tier").value = member.tier;
  }

  $("#btn-admin-scan").addEventListener("click", async () => {
    const btn = $("#btn-admin-scan");
    btn.disabled = true;
    btn.textContent = "Scanning…";
    setOrb($("#admin-orb"), "scanning");
    setMsg($("#admin-msg"), "Reading card…");

    try {
      const data = await api("/api/admin/scan", { method: "POST", body: "{}" });
      fillAdminForm(data.member);
      setOrb($("#admin-orb"), "valid");
      const mode = data.mode === "simulation" ? " (simulation)" : "";
      setMsg(
        $("#admin-msg"),
        `Loaded ${data.member.name} · ${data.member.member_id}${mode}`,
        "is-ok"
      );
    } catch (e) {
      setOrb($("#admin-orb"), "error");
      setMsg($("#admin-msg"), e.message, "is-error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Scan card into form";
    }
  });

  function clearAdminForm(defaults = {}) {
    $("#admin-name").value = "";
    $("#admin-id").value = "";
    $("#admin-points").value = defaults.loyalty_points ?? 0;
    $("#admin-start").value = defaults.start_date || "";
    $("#admin-end").value = defaults.end_date || "";
    $("#admin-status").value = defaults.status || "Active";
    $("#admin-tier").value = defaults.tier || "Gold";
    $("#admin-write-card").checked = true;
    setOrb($("#admin-orb"), null);
    setMsg($("#admin-msg"), "Form cleared.");
  }

  $("#btn-clear-form").addEventListener("click", async () => {
    try {
      const data = await api("/api/defaults");
      clearAdminForm(data.defaults);
    } catch {
      clearAdminForm();
    }
  });

  $("#admin-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = $("#btn-write");
    btn.disabled = true;
    setOrb($("#admin-orb"), "scanning");
    setMsg($("#admin-msg"), "Encrypting and writing…");

    const body = {
      name: $("#admin-name").value.trim(),
      member_id: $("#admin-id").value.trim(),
      loyalty_points: Number($("#admin-points").value || 0),
      start_date: $("#admin-start").value,
      end_date: $("#admin-end").value,
      status: $("#admin-status").value,
      tier: $("#admin-tier").value,
      write_card: $("#admin-write-card").checked,
    };

    try {
      const data = await api("/api/admin/create", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setOrb($("#admin-orb"), "valid");
      const mode = data.mode === "simulation" ? " (simulation)" : "";
      setMsg(
        $("#admin-msg"),
        `Created ${data.member.name} · ${data.member.member_id}${mode}`,
        "is-ok"
      );
    } catch (e) {
      setOrb($("#admin-orb"), "error");
      setMsg($("#admin-msg"), e.message, "is-error");
    } finally {
      btn.disabled = false;
    }
  });

  // ---- Data Base ----
  let searchTimer = null;

  async function refreshDbSession() {
    try {
      const data = await api("/api/db/session");
      setDbUnlocked(!!data.authenticated);
      if (data.authenticated) loadMembers();
    } catch {
      setDbUnlocked(false);
    }
  }

  function setDbUnlocked(unlocked) {
    $("#db-gate").hidden = unlocked;
    $("#db-workspace").hidden = !unlocked;
  }

  $("#btn-db-login").addEventListener("click", async () => {
    const password = $("#db-password").value;
    setMsg($("#db-login-msg"), "Checking…");
    try {
      await api("/api/db/login", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      $("#db-password").value = "";
      setMsg($("#db-login-msg"), "");
      setDbUnlocked(true);
      loadMembers();
    } catch (e) {
      setMsg($("#db-login-msg"), e.message || "Incorrect password", "is-error");
    }
  });

  $("#db-password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#btn-db-login").click();
  });

  $("#btn-db-logout").addEventListener("click", async () => {
    await api("/api/db/logout", { method: "POST", body: "{}" });
    setDbUnlocked(false);
  });

  async function loadMembers() {
    const ul = $("#members-ul");
    const countEl = $("#db-count");
    const q = ($("#db-search")?.value || "").trim();
    if (!ul) return;

    ul.innerHTML = "<li class='member-card muted'>Loading…</li>";
    try {
      const url = q
        ? `/api/db/members?q=${encodeURIComponent(q)}`
        : "/api/db/members";
      const data = await api(url);
      if (countEl) {
        countEl.textContent = q
          ? `${data.count} result${data.count === 1 ? "" : "s"} for “${q}”`
          : `${data.count} member${data.count === 1 ? "" : "s"}`;
      }
      if (!data.members.length) {
        ul.innerHTML = `<li class="member-card muted">${
          q ? "No members match this search." : "No members stored yet."
        }</li>`;
        return;
      }
      ul.innerHTML = data.members.map(renderMemberCard).join("");
    } catch (e) {
      if (countEl) countEl.textContent = "";
      ul.innerHTML = `<li class="member-card muted">${escapeHtml(e.message)}</li>`;
    }
  }

  function renderMemberCard(m) {
    return `<li class="member-card">
      <details class="member-details">
        <summary class="member-summary">
          <span class="member-summary__text">
            <strong>${escapeHtml(m.name)}</strong>
            <span class="member-summary__id">${escapeHtml(m.member_id)}</span>
          </span>
          <span class="member-summary__chevron" aria-hidden="true"></span>
        </summary>
        <dl class="member-card__grid">
          <div><dt>Points</dt><dd>${escapeHtml(m.loyalty_points)}</dd></div>
          <div><dt>Tier</dt><dd>${escapeHtml(m.tier || "—")}</dd></div>
          <div><dt>Status</dt><dd>${escapeHtml(m.status || "—")}</dd></div>
          <div><dt>Card UID</dt><dd>${escapeHtml(m.card_uid || "—")}</dd></div>
          <div><dt>Start</dt><dd>${escapeHtml(m.start_date || "—")}</dd></div>
          <div><dt>End</dt><dd>${escapeHtml(m.end_date || "—")}</dd></div>
          <div><dt>Created</dt><dd>${escapeHtml(m.created_at || "—")}</dd></div>
          <div><dt>Updated</dt><dd>${escapeHtml(m.updated_at || "—")}</dd></div>
        </dl>
      </details>
    </li>`;
  }

  $("#btn-refresh-members").addEventListener("click", loadMembers);

  $("#db-search")?.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(loadMembers, 220);
  });

  // ---- Boot ----
  async function boot() {
    await refreshReader();
    try {
      const data = await api("/api/defaults");
      $("#admin-start").value = data.defaults.start_date;
      $("#admin-end").value = data.defaults.end_date;
      $("#admin-points").value = data.defaults.loyalty_points;
      menuItems = data.menu || [];
      fillMenuSelect();
    } catch {
      /* ignore */
    }
    refreshAdminSession();
    refreshDbSession();
  }

  boot();
})();
