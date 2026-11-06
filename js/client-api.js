/**
 * Browser-only CUPPEE backend for GitHub Pages.
 * AES-128 (Web Crypto) + localStorage membership DB + simulated NFC.
 */
(() => {
  "use strict";

  const ADMIN_PASSWORD = "cohee2026";
  const POINTS_PER_DOLLAR = 1;
  const STORAGE_KEY = "cuppee_pages_db_v2";
  const CARD_KEY_STR = "CoHeeCUPPEEKey!!"; // 16 chars → AES-128
  const DB_KEY_STR = "CoHeeDBSecretKey";

  const MENU = [
    { id: "americano", name: "Americano", price: 32 },
    { id: "latte", name: "Latte", price: 38 },
    { id: "cappuccino", name: "Cappuccino", price: 38 },
    { id: "flat_white", name: "Flat White", price: 40 },
    { id: "mocha", name: "Mocha", price: 42 },
    { id: "espresso", name: "Espresso", price: 28 },
    { id: "cold_brew", name: "Cold Brew", price: 42 },
    { id: "matcha_latte", name: "Matcha Latte", price: 42 },
    { id: "hot_chocolate", name: "Hot Chocolate", price: 36 },
    { id: "croissant", name: "Butter Croissant", price: 28 },
    { id: "pain_chocolat", name: "Pain au Chocolat", price: 30 },
    { id: "banana_bread", name: "Banana Bread", price: 32 },
    { id: "cookie", name: "Cookie", price: 18 },
    { id: "sandwich", name: "Ham & Cheese Sandwich", price: 48 },
  ];

  const FIRST = [
    "Alex", "Jamie", "Sam", "Chris", "Taylor", "Jordan", "Casey", "Morgan",
    "Riley", "Avery", "Quinn", "Harper", "Kai", "Nova", "Ellis", "Reese",
  ];
  const LAST = [
    "Wong", "Chan", "Lee", "Cheung", "Lam", "Ho", "Ng", "Cheng",
    "Leung", "Lau", "Yip", "Tang", "Mak", "Kwok", "Tsang", "Fung",
  ];
  const TIERS = ["Silver", "Gold", "Platinum"];
  const STATUSES = ["Active", "Active", "Active", "Expired", "Suspended"];

  const session = {
    admin_ok: false,
    db_ok: false,
    card: null, // { uid, member }
  };

  function todayISO() {
    return new Date().toISOString().slice(0, 10);
  }

  function nowISO() {
    return new Date().toISOString().slice(0, 19);
  }

  function loadStore() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    } catch {
      return {};
    }
  }

  function saveStore(store) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  }

  function getStore() {
    const s = loadStore();
    if (!s.members) s.members = {};
    if (!s.purchases) s.purchases = [];
    return s;
  }

  let seedPromise = null;

  async function ensureSeeded() {
    const store = getStore();
    if (store.seeded_12) return;
    if (seedPromise) return seedPromise;

    seedPromise = (async () => {
      const year = new Date().getFullYear();
      for (let i = 0; i < 12; i++) {
        const member = randomMember();
        member.member_id = `CP-${year}-${10001 + i}`;
        // Prefer distinct demo names from the name lists
        member.name = `${FIRST[i % FIRST.length]} ${LAST[i % LAST.length]}`;
        member.status = STATUSES[i % STATUSES.length];
        member.tier = TIERS[i % TIERS.length];
        const uid = randomUid();
        await upsertMember(member, uid);
      }
      const s = getStore();
      s.seeded_12 = true;
      saveStore(s);
    })();

    return seedPromise;
  }

  async function importAesKey(str) {
    const bytes = new TextEncoder().encode(str.padEnd(16, "\0").slice(0, 16));
    return crypto.subtle.importKey("raw", bytes, { name: "AES-CBC" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  function b64encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function b64decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function encryptJson(keyStr, obj) {
    const key = await importAesKey(keyStr);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const plain = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, plain);
    const packed = new Uint8Array(iv.length + ct.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ct), 16);
    return b64encode(packed);
  }

  async function decryptJson(keyStr, token) {
    const key = await importAesKey(keyStr);
    const packed = b64decode(token);
    const iv = packed.slice(0, 16);
    const ct = packed.slice(16);
    const plain = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function randomMember() {
    const name = `${pick(FIRST)} ${pick(LAST)}`;
    const year = new Date().getFullYear();
    const member_id = `CP-${year}-${Math.floor(10000 + Math.random() * 90000)}`;
    let status = pick(STATUSES);
    const start = new Date();
    start.setDate(start.getDate() - Math.floor(Math.random() * 400));
    let end = new Date(start);
    end.setDate(end.getDate() + 365);
    if (status === "Expired") {
      end = new Date();
      end.setDate(end.getDate() - Math.floor(1 + Math.random() * 90));
      start.setTime(end.getTime());
      start.setDate(start.getDate() - 365);
    }
    return {
      name,
      member_id,
      loyalty_points: Math.floor(Math.random() * 2501),
      start_date: start.toISOString().slice(0, 10),
      end_date: end.toISOString().slice(0, 10),
      status,
      tier: pick(TIERS),
    };
  }

  function randomUid() {
    const hex = [...crypto.getRandomValues(new Uint8Array(4))]
      .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
      .join("");
    return `SIM-${hex}`;
  }

  function availability(member) {
    const status = String(member.status || "").toLowerCase();
    let isExpired = status === "expired";
    try {
      if (member.end_date) {
        isExpired = isExpired || new Date(member.end_date) < new Date(todayISO());
      }
    } catch {
      /* ignore */
    }
    if (status === "suspended") return { state: "suspended", label: "Suspended", is_active: false };
    if (isExpired) return { state: "expired", label: "Expired", is_active: false };
    return { state: "valid", label: "Valid", is_active: true };
  }

  async function upsertMember(member, cardUid) {
    const store = getStore();
    const id = String(member.member_id).trim();
    const payload = {
      name: member.name || "",
      member_id: id,
      loyalty_points: Number(member.loyalty_points || 0),
      start_date: member.start_date || "",
      end_date: member.end_date || "",
      status: member.status || "Active",
      tier: member.tier || "Gold",
    };
    const enc = await encryptJson(DB_KEY_STR, payload);
    const prev = store.members[id];
    const now = nowISO();
    store.members[id] = {
      member_id: id,
      card_uid: cardUid || (prev && prev.card_uid) || null,
      payload_enc: enc,
      created_at: (prev && prev.created_at) || now,
      updated_at: now,
    };
    saveStore(store);
    return payload;
  }

  async function listMembersDecrypted() {
    const store = getStore();
    const out = [];
    for (const row of Object.values(store.members)) {
      try {
        const data = await decryptJson(DB_KEY_STR, row.payload_enc);
        data.card_uid = row.card_uid;
        data.created_at = row.created_at;
        data.updated_at = row.updated_at;
        out.push(data);
      } catch {
        /* skip corrupt */
      }
    }
    out.sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
    return out;
  }

  function listPurchases(memberId, limit = 10) {
    const store = getStore();
    return store.purchases
      .filter((p) => !memberId || p.member_id === memberId)
      .slice()
      .reverse()
      .slice(0, limit);
  }

  function menuById(id) {
    return MENU.find((m) => m.id === id) || null;
  }

  function ok(data) {
    return { ok: true, ...data };
  }

  function fail(error, status = 400) {
    const err = new Error(error);
    err.status = status;
    err.data = { ok: false, error };
    throw err;
  }

  function parseBody(options) {
    if (!options || options.body == null || options.body === "") return {};
    if (typeof options.body === "string") {
      try {
        return JSON.parse(options.body);
      } catch {
        return {};
      }
    }
    return options.body;
  }

  function pathOf(url) {
    const u = String(url);
    const q = u.indexOf("?");
    const path = q >= 0 ? u.slice(0, q) : u;
    return path.replace(/^https?:\/\/[^/]+/, "");
  }

  function queryOf(url) {
    const u = String(url);
    const q = u.indexOf("?");
    if (q < 0) return {};
    return Object.fromEntries(new URLSearchParams(u.slice(q + 1)));
  }

  async function handle(url, options = {}) {
    await ensureSeeded();

    const method = (options.method || "GET").toUpperCase();
    const path = pathOf(url);
    const query = queryOf(url);
    const body = parseBody(options);

    // delay slightly so UI feels like a scan
    if (path.includes("/scan") || path.includes("/create") || path.includes("/purchase")) {
      await new Promise((r) => setTimeout(r, 280));
    }

    if (path === "/api/reader") {
      return ok({
        mode: "simulation",
        reader: "GitHub Pages · browser simulation",
      });
    }

    if (path === "/api/defaults") {
      const end = new Date();
      end.setDate(end.getDate() + 365);
      return ok({
        defaults: {
          start_date: todayISO(),
          end_date: end.toISOString().slice(0, 10),
          loyalty_points: 0,
          status: "Active",
          tier: "Gold",
          points_per_dollar: POINTS_PER_DOLLAR,
        },
        menu: MENU,
      });
    }

    if (path === "/api/menu") return ok({ menu: MENU });

    if (path === "/api/admin/login" && method === "POST") {
      if (body.password !== ADMIN_PASSWORD) fail("Incorrect password", 401);
      session.admin_ok = true;
      return ok({});
    }
    if (path === "/api/admin/logout" && method === "POST") {
      session.admin_ok = false;
      return ok({});
    }
    if (path === "/api/admin/session") {
      return ok({ authenticated: !!session.admin_ok });
    }

    if (path === "/api/db/login" && method === "POST") {
      if (body.password !== ADMIN_PASSWORD) fail("Incorrect password", 401);
      session.db_ok = true;
      return ok({});
    }
    if (path === "/api/db/logout" && method === "POST") {
      session.db_ok = false;
      return ok({});
    }
    if (path === "/api/db/session") {
      return ok({ authenticated: !!session.db_ok });
    }

    if (path === "/api/db/members") {
      if (!session.db_ok) fail("Database authentication required", 401);
      let members = await listMembersDecrypted();
      const q = (query.q || "").trim().toLowerCase();
      if (q) {
        members = members.filter((m) =>
          ["name", "member_id", "loyalty_points", "start_date", "end_date", "status", "tier", "card_uid"]
            .map((k) => String(m[k] ?? "").toLowerCase())
            .join(" ")
            .includes(q)
        );
      }
      return ok({ members, count: members.length, query: query.q || "" });
    }

    if (path === "/api/check/scan" && method === "POST") {
      const member = randomMember();
      const uid = randomUid();
      session.card = { uid, member: { ...member } };
      await upsertMember(member, uid);
      return ok({
        uid,
        mode: "simulation",
        member,
        availability: availability(member),
        purchases: listPurchases(member.member_id, 10),
      });
    }

    if (path === "/api/admin/scan" && method === "POST") {
      if (!session.admin_ok) fail("Admin authentication required", 401);
      const member = randomMember();
      const uid = randomUid();
      session.card = { uid, member: { ...member } };
      await upsertMember(member, uid);
      return ok({ uid, mode: "simulation", member });
    }

    if (path === "/api/admin/generate-id" && method === "POST") {
      if (!session.admin_ok) fail("Admin authentication required", 401);
      const id = `CP-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
      return ok({ member_id: id });
    }

    if (path === "/api/admin/create" && method === "POST") {
      if (!session.admin_ok) fail("Admin authentication required", 401);
      const member = {
        name: (body.name || "").trim(),
        member_id: (body.member_id || "").trim(),
        loyalty_points: Number(body.loyalty_points || 0),
        start_date: body.start_date || todayISO(),
        end_date: body.end_date || todayISO(),
        status: body.status || "Active",
        tier: body.tier || "Gold",
      };
      if (!member.name || !member.member_id) fail("Name and Member ID are required");
      let uid = null;
      let card = null;
      if (body.write_card !== false) {
        uid = randomUid();
        session.card = { uid, member: { ...member } };
        card = {
          uid,
          member,
          bytes_written: 86,
          mode: "simulation",
        };
      }
      const saved = await upsertMember(member, uid);
      return ok({ member: saved, card, mode: card ? "simulation" : null });
    }

    if (path === "/api/check/purchase" && method === "POST") {
      const memberId = (body.member_id || "").trim();
      const menuItem = menuById(body.menu_item_id);
      if (!memberId) fail("member_id is required");
      if (!menuItem) fail("Select a menu item");

      const amount = Number(menuItem.price);
      const pointsEarned = Math.round(amount * POINTS_PER_DOLLAR);
      const store = getStore();

      let basePoints = Number(body.loyalty_points || 0);
      if (store.members[memberId]) {
        try {
          const dec = await decryptJson(DB_KEY_STR, store.members[memberId].payload_enc);
          basePoints = Number(dec.loyalty_points || 0);
        } catch {
          /* use body */
        }
      } else {
        await upsertMember(
          {
            name: body.name || "",
            member_id: memberId,
            loyalty_points: basePoints,
            start_date: body.start_date || "",
            end_date: body.end_date || "",
            status: body.status || "Active",
            tier: body.tier || "Gold",
          },
          session.card && session.card.member.member_id === memberId
            ? session.card.uid
            : null
        );
      }

      const newPoints = basePoints + pointsEarned;
      const purchase = {
        id: Date.now(),
        member_id: memberId,
        items: { id: menuItem.id, name: menuItem.name, price: menuItem.price },
        amount,
        points_earned: pointsEarned,
        purchased_at: nowISO(),
      };
      store.purchases.push(purchase);
      saveStore(store);

      await upsertMember(
        {
          name: body.name || (session.card && session.card.member.name) || "",
          member_id: memberId,
          loyalty_points: newPoints,
          start_date: body.start_date || "",
          end_date: body.end_date || "",
          status: body.status || "Active",
          tier: body.tier || "Gold",
        },
        session.card && session.card.member.member_id === memberId
          ? session.card.uid
          : null
      );

      let cardUpdated = false;
      let cardError = null;
      let card = null;
      if (body.update_card !== false) {
        if (session.card && session.card.member.member_id === memberId) {
          session.card.member.loyalty_points = newPoints;
          cardUpdated = true;
          card = { uid: session.card.uid, member: session.card.member, mode: "simulation" };
        } else {
          cardError = "No matching simulated card in this session";
        }
      }

      return ok({
        purchase,
        loyalty_points: newPoints,
        points_earned: pointsEarned,
        card_updated: cardUpdated,
        card_error: cardError,
        card,
      });
    }

    fail(`Unknown API route: ${method} ${path}`, 404);
  }

  window.CuppeeClient = { handle, STATIC: true };
})();
