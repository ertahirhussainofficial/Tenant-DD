/**
 * Tenant Identity Card — Cloudflare Worker backend
 * Firebase RTDB (via REST + database secret) + Telegram (file storage) + HMAC QR tokens + HS256 JWT.
 *
 * Roles:  admin (you, ADMIN_KEY) → landlord (phone+PIN) → viewer (loginId+PIN, created by landlord)
 */

let CTX = null;   // current request context (for fire-and-forget alerts)

export default {
  async fetch(request, env, ctx) {
    CTX = ctx;
    try {
      return await route(request, env, ctx);
    } catch (e) {
      const status = e.status || 500;
      return json({ ok: false, error: e.message || String(e) }, status);
    }
  }
};

/* ============================ ROUTER ============================ */

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  // Android HttpURLConnection cannot send PATCH/DELETE bodies → app sends POST + override header
  const m = (request.method === "POST" && request.headers.get("X-HTTP-Method-Override")) || request.method;

  if (m === "OPTIONS") return cors(new Response(null, { status: 204 }));

  // ---------- Public ----------
  if (m === "GET" && p === "/") return html(landing(env));
  let x;
  if ((x = match(p, "/v/:token")) && m === "GET") return publicPage(request, env, ctx, x.token, url);
  if ((x = match(p, "/api/v/:token")) && m === "GET") return publicJson(request, env, ctx, x.token, url);
  if ((x = match(p, "/photo/:token")) && m === "GET") return publicPhoto(env, x.token);
  if ((x = match(p, "/sig/:token")) && m === "GET") return publicStamp(env, x.token, "signature");
  if ((x = match(p, "/seal/:token")) && m === "GET") return publicStamp(env, x.token, "seal");
  if ((x = match(p, "/logo/:token")) && m === "GET") return publicLogo(env, x.token);
  if ((x = match(p, "/vault/:tid/:idx")) && m === "GET") return vaultFile(env, x.tid, x.idx, url);
  if ((x = match(p, "/c/:cardNo")) && m === "GET") return cardLookup(env, x.cardNo);
  if ((x = match(p, "/qr/:token")) && m === "GET") return qrSvg(env.BASE_URL + "/v/" + x.token);
  if (p === "/logo.png" && m === "GET") { if (env.DEFAULT_LOGO_URL) return Response.redirect(env.DEFAULT_LOGO_URL, 302); throw err(404, "no default logo"); }
  if (p === "/app/version" && m === "GET") return json({ ok: true, version: Number(env.APP_VERSION || 1), apkUrl: env.APK_URL || "", notes: env.APP_NOTES || "" });

  // ---------- Auth ----------
  if (p === "/auth/login" && m === "POST") return authAny(request, env);        // one login for all roles
  if (p === "/auth/landlord" && m === "POST") return authLandlord(request, env);
  if (p === "/auth/viewer" && m === "POST") return authViewer(request, env);

  // ---------- Super admin (you): Firebase email+password login, or X-Admin-Key for curl ----------
  if (p.startsWith("/admin/")) {
    if (request.headers.get("X-Admin-Key") !== env.ADMIN_KEY) await auth(request, env, "admin");
    if (p === "/admin/landlord" && m === "POST") return adminCreateLandlord(request, env);
    if (p === "/admin/landlords" && m === "GET") return json({ ok: true, landlords: strip(await fbGet(env, "landlords")) });
    if ((x = match(p, "/admin/landlord/:lid")) && m === "PATCH") return adminPatchLandlord(request, env, x.lid);
    if (p === "/admin/overview" && m === "GET") return adminOverview(env);
    if ((x = match(p, "/admin/landlord/:lid/tenants")) && m === "GET") return json({ ok: true, tenants: withStatus(await fbQuery(env, "tenants", "lid", x.lid)) });
    if ((x = match(p, "/admin/landlord/:lid/viewers")) && m === "GET") return json({ ok: true, viewers: strip(await fbQuery(env, "viewers", "lid", x.lid)) });
    if ((x = match(p, "/admin/landlord/:lid/token")) && m === "POST") {          // open a landlord's workspace as admin
      const L = await fbGet(env, "landlords/" + x.lid); if (!L) throw err(404, "landlord not found");
      const token = await jwtSign(env, { role: "landlord", lid: x.lid, name: L.name, actingAdmin: true }, 4 * 3600);
      return json({ ok: true, token, lid: x.lid, name: L.name });
    }
    if (p === "/admin/feed" && m === "GET") return json({ ok: true, feed: await fbGet(env, "adminFeed", { orderBy: '"at"', limitToLast: 50 }) || {} });
  }

  // ---------- Landlord ----------
  if (p.startsWith("/landlord/")) {
    const u = await auth(request, env, "landlord");
    if (p === "/landlord/me" && m === "GET") return json({ ok: true, me: strip1(await fbGet(env, "landlords/" + u.lid)), actingAdmin: !!u.actingAdmin });
    if (p === "/landlord/me" && m === "PATCH") return patchMe(request, env, u);
    if (p === "/landlord/pin" && m === "POST") return changePin(request, env, u);
    if (p === "/landlord/tg-test" && m === "POST") {
      const L = await fbGet(env, "landlords/" + u.lid);
      if (!L.tgChatId) throw err(400, "Save your Telegram ID first");
      const r = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: L.tgChatId, text: `✅ ${env.APP_NAME || "Tenant Card"}: alerts are linked for ${L.name}. You will receive a message on every scan and official note.` }) });
      const j = await r.json(); if (!j.ok) throw err(400, "Telegram says: " + (j.description || "failed") + ". Did you press Start on the bot?");
      return json({ ok: true });
    }
    if (p === "/landlord/dashboard" && m === "GET") return dashboard(env, u);
    if (p === "/landlord/rooms" && m === "GET") return rooms(env, u);
    if (p === "/landlord/feed" && m === "GET") return json({ ok: true, feed: await fbGet(env, "feed/" + u.lid, { orderBy: '"at"', limitToLast: 100 }) || {} });
    if (p === "/landlord/export.csv" && m === "GET") return exportCsv(env, u, url.searchParams.get("tid"));
    if ((x = match(p, "/landlord/property/:pid")) && m === "DELETE") return deleteProperty(env, u, x.pid);
    if ((x = match(p, "/landlord/viewer/:vid")) && m === "DELETE") return deleteViewer(env, u, x.vid);
    if (p === "/landlord/property" && m === "POST") return createProperty(request, env, u);
    if ((x = match(p, "/landlord/property/:pid")) && m === "PATCH") return patchProperty(request, env, u, x.pid);
    if (p === "/landlord/properties" && m === "GET") return json({ ok: true, properties: await fbQuery(env, "properties", "lid", u.lid) });
    if (p === "/landlord/tenant" && m === "POST") return createTenant(request, env, u);
    if ((x = match(p, "/landlord/tenant/:tid")) && m === "GET") {
      const T = await ownTenant(env, u, x.tid);
      const token = await cardToken(env, x.tid, T.tokenVer || 1);
      const L = await fbGet(env, "landlords/" + u.lid);
      const P = await fbGet(env, "properties/" + T.pid);
      return json({ ok: true, tenant: { ...T, effStatus: effStatus(T) }, token, qrUrl: env.BASE_URL + "/v/" + token,
        property: P || {}, landlord: { name: L.name, phone: L.phone, helpline: L.helpline || "", hasSignature: !!L.signature, hasSeal: !!L.seal },
        card: cardSettings(env, L, P || {}), logoUrl: P && P.logo ? env.BASE_URL + "/logo/" + token + ver(P.logo) : null,
        photoUrl: T.photo ? env.BASE_URL + "/photo/" + token + ver(T.photo) : null,
        sigUrl: L.signature ? env.BASE_URL + "/sig/" + token + ver(L.signature) : null,
        sealUrl: L.seal ? env.BASE_URL + "/seal/" + token + ver(L.seal) : null });
    }
    if ((x = match(p, "/landlord/tenant/:tid")) && m === "PATCH") return patchTenant(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/photo")) && m === "POST") return uploadPhoto(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/vault")) && m === "POST") return uploadVault(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/vault/:idx")) && m === "DELETE") return deleteVault(env, u, x.tid, x.idx);
    if ((x = match(p, "/landlord/tenant/:tid/vault")) && m === "GET") return listVault(env, u, x.tid);
    if (p === "/landlord/tenants" && m === "GET") return json({ ok: true, tenants: await withLinks(env, withStatus(await fbQuery(env, "tenants", "lid", u.lid))) });
    if ((x = match(p, "/landlord/logs/:tid")) && m === "GET") return tenantLogs(env, u, x.tid);
    if (p === "/landlord/viewer" && m === "POST") return createViewer(request, env, u);
    if ((x = match(p, "/landlord/viewer/:vid")) && m === "PATCH") return patchViewer(request, env, u, x.vid);
    if (p === "/landlord/viewers" && m === "GET") return json({ ok: true, viewers: strip(await fbQuery(env, "viewers", "lid", u.lid)) });
    if (p === "/landlord/signature" && m === "POST") return uploadLandlordImage(request, env, u, "signature");
    if (p === "/landlord/seal" && m === "POST") return uploadLandlordImage(request, env, u, "seal");
    if ((x = match(p, "/landlord/image/:kind")) && m === "GET") return landlordImage(env, u, x.kind);
    if ((x = match(p, "/landlord/property/:pid/logo")) && m === "POST") return uploadPropertyLogo(request, env, u, x.pid);
    if ((x = match(p, "/landlord/property/:pid/logo")) && m === "DELETE") { const P = await fbGet(env, "properties/" + x.pid); if (!P || P.lid !== u.lid) throw err(404, "property not found"); await fbPatch(env, "properties/" + x.pid, { logo: null }); return json({ ok: true }); }
    if ((x = match(p, "/landlord/property/:pid/logo")) && m === "GET") { const P = await fbGet(env, "properties/" + x.pid); if (!P || P.lid !== u.lid || !P.logo) throw err(404, "no logo"); return tgServe(env, P.logo.file_id, P.logo.mime); }
  }

  // ---------- Viewer (police / administration) ----------
  if (p.startsWith("/viewer/")) {
    const u = await auth(request, env, "viewer");
    if (p === "/viewer/me" && m === "GET") return json({ ok: true, me: strip1(await fbGet(env, "viewers/" + u.vid)) });
    if (p === "/viewer/scan" && m === "POST") return viewerScan(request, env, u);
    if (p === "/viewer/note" && m === "POST") return viewerNote(request, env, u);
    if (p === "/viewer/tenants" && m === "GET") return viewerTenants(env, u);
    if ((x = match(p, "/viewer/tenant/:tid")) && m === "GET") return viewerTenant(request, env, u, x.tid);
    if (p === "/viewer/myscans" && m === "GET") return json({ ok: true, scans: await fbGet(env, "viewerScans/" + u.vid, { orderBy: '"at"', limitToLast: 100 }) });
  }

  throw err(404, "not found");
}

/* ============================ AUTH ============================ */

/** One login box: email → super-admin (Firebase Auth); digits → landlord phone; anything else → viewer loginId. */
async function authAny(request, env) {
  const b = await request.json();
  const id = String(b.id || b.loginId || b.phone || b.email || "").trim();
  const pw = String(b.password || b.pin || "").trim();
  if (!id || !pw) throw err(400, "id and password required");
  const fkey = "fails/" + id.toLowerCase().replace(/[^a-z0-9]/g, "_").slice(0, 60);
  const f = (await fbGet(env, fkey)) || { n: 0, at: 0 };
  if (f.n >= 5 && Date.now() - f.at < 10 * 60000) throw err(429, "Too many attempts. Try again in " + Math.ceil((10 * 60000 - (Date.now() - f.at)) / 60000) + " min");
  try {
    const res = await authAnyInner(env, id, pw);
    if (f.n) await fbDelete(env, fkey);
    return res;
  } catch (e) {
    if (e.status === 401) await fbPut(env, fkey, { n: (Date.now() - f.at < 10 * 60000 ? f.n : 0) + 1, at: Date.now() });
    throw e;
  }
}

async function authAnyInner(env, id, pw) {

  if (id.includes("@")) {
    if (!env.FB_API_KEY) throw err(500, "FB_API_KEY not set");
    const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${env.FB_API_KEY}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: id, password: pw, returnSecureToken: true })
    });
    const j = await r.json();
    if (!r.ok || !j.localId) {
      const code = j.error?.message || "";
      const why = { OPERATION_NOT_ALLOWED: "Enable Email/Password sign-in in Firebase Authentication", EMAIL_NOT_FOUND: "No such admin user in Firebase Auth",
        INVALID_PASSWORD: "Wrong password", INVALID_LOGIN_CREDENTIALS: "Wrong email or password", USER_DISABLED: "Admin user disabled",
        API_KEY_INVALID: "FB_API_KEY is wrong", TOO_MANY_ATTEMPTS_TRY_LATER: "Too many attempts, wait a few minutes" }[code.split(" ")[0]];
      throw err(401, why || ("Admin login failed: " + code));
    }
    if (env.ADMIN_EMAILS && !env.ADMIN_EMAILS.toLowerCase().split(",").map(s => s.trim()).includes(id.toLowerCase())) throw err(403, "not an admin");
    const token = await jwtSign(env, { role: "admin", email: id, name: j.displayName || id.split("@")[0] }, 12 * 3600);
    return json({ ok: true, role: "admin", token, name: j.displayName || id.split("@")[0] });
  }

  if (/^\+?\d{8,15}$/.test(id)) {
    const rows = await fbQuery(env, "landlords", "phone", id.replace(/^\+91/, ""));
    const [lid, L] = Object.entries(rows)[0] || [];
    if (!L) throw err(401, "No landlord with this phone number");
    if (L.status !== "active") throw err(401, "Landlord account disabled");
    if (!(await verifyPin(pw, L.pinHash, L.pinSalt))) throw err(401, "Wrong password");
    const token = await jwtSign(env, { role: "landlord", lid, name: L.name }, 12 * 3600);
    return json({ ok: true, role: "landlord", token, lid, name: L.name });
  }

  const rows = await fbQuery(env, "viewers", "loginId", id.toLowerCase());
  const [vid, V] = Object.entries(rows)[0] || [];
  if (!V) throw err(401, "No official login with this ID");
  if (V.status !== "active") throw err(401, "Login disabled by landlord");
  if (V.expiresAt && Date.now() > V.expiresAt) throw err(401, "Access expired — contact landlord");
  if (!(await verifyPin(pw, V.pinHash, V.pinSalt))) throw err(401, "Wrong password");
  const token = await jwtSign(env, { role: "viewer", vid, lid: V.lid, name: V.name, dept: V.dept, perms: V.perms || {} }, 8 * 3600);
  return json({ ok: true, role: "viewer", token, vid, name: V.name, dept: V.dept, perms: V.perms || {} });
}

async function adminOverview(env) {
  const [L, T, V] = await Promise.all([fbGet(env, "landlords"), fbGet(env, "tenants"), fbGet(env, "viewers")]);
  const out = { landlords: 0, tenants: 0, active: 0, revoked: 0, viewers: 0, perLandlord: {} };
  for (const lid in (L || {})) { out.landlords++; out.perLandlord[lid] = { name: L[lid].name, phone: L[lid].phone, status: L[lid].status, tenants: 0, active: 0, viewers: 0 }; }
  for (const tid in (T || {})) { const t = T[tid]; out.tenants++; const s = effStatus(t); if (s === "active") out.active++; if (s === "revoked") out.revoked++;
    const pl = out.perLandlord[t.lid]; if (pl) { pl.tenants++; if (s === "active") pl.active++; } }
  for (const vid in (V || {})) { out.viewers++; const pl = out.perLandlord[V[vid].lid]; if (pl) pl.viewers++; }
  return json({ ok: true, ...out });
}

async function authLandlord(request, env) {
  const { phone, pin } = await request.json();
  if (!phone || !pin) throw err(400, "phone and pin required");
  const rows = await fbQuery(env, "landlords", "phone", String(phone));
  const [lid, L] = Object.entries(rows)[0] || [];
  if (!L || L.status !== "active") throw err(401, "login failed");
  if (!(await verifyPin(pin, L.pinHash, L.pinSalt))) throw err(401, "login failed");
  const token = await jwtSign(env, { role: "landlord", lid, name: L.name }, 12 * 3600);
  return json({ ok: true, token, lid, name: L.name });
}

async function authViewer(request, env) {
  const { loginId, pin } = await request.json();
  if (!loginId || !pin) throw err(400, "loginId and pin required");
  const rows = await fbQuery(env, "viewers", "loginId", String(loginId).toLowerCase());
  const [vid, V] = Object.entries(rows)[0] || [];
  if (!V || V.status !== "active") throw err(401, "login failed");
  if (V.expiresAt && Date.now() > V.expiresAt) throw err(401, "access expired — contact landlord");
  if (!(await verifyPin(pin, V.pinHash, V.pinSalt))) throw err(401, "login failed");
  const token = await jwtSign(env, { role: "viewer", vid, lid: V.lid, name: V.name, dept: V.dept, perms: V.perms || {} }, 8 * 3600);
  return json({ ok: true, token, vid, name: V.name, dept: V.dept, perms: V.perms || {} });
}

async function auth(request, env, role) {
  const h = request.headers.get("Authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const u = await jwtVerify(env, t);
  if (!u || u.role !== role) throw err(401, "unauthorized");
  return u;
}

/* ============================ SUPER ADMIN ============================ */

async function adminCreateLandlord(request, env) {
  const b = await request.json();
  if (!b.name || !b.phone || !b.pin) throw err(400, "name, phone, pin required");
  const dup = await fbQuery(env, "landlords", "phone", String(b.phone));
  if (Object.keys(dup).length) throw err(409, "phone already registered");
  const { hash, salt } = await hashPin(b.pin);
  const lid = id("L");
  await fbPut(env, "landlords/" + lid, {
    name: b.name, phone: String(b.phone), pinHash: hash, pinSalt: salt,
    status: "active", createdAt: Date.now()
  });
  return json({ ok: true, lid });
}

async function adminPatchLandlord(request, env, lid) {
  const b = await request.json();
  const patch = {};
  if (b.status) patch.status = b.status;
  if (b.name) patch.name = b.name;
  if (b.pin) { const { hash, salt } = await hashPin(b.pin); patch.pinHash = hash; patch.pinSalt = salt; }
  await fbPatch(env, "landlords/" + lid, patch);
  return json({ ok: true });
}

/* ============================ LANDLORD ============================ */

async function createProperty(request, env, u) {
  const b = await request.json();
  if (!b.address) throw err(400, "address required");
  const pid = id("P");
  await fbPut(env, "properties/" + pid, {
    lid: u.lid, label: b.label || "", address: b.address,
    policeStation: b.policeStation || "", rooms: toRooms(b.rooms), createdAt: Date.now()
  });
  return json({ ok: true, pid });
}

async function patchProperty(request, env, u, pid) {
  const P = await fbGet(env, "properties/" + pid);
  if (!P || P.lid !== u.lid) throw err(404, "property not found");
  const b = await request.json();
  const patch = {};
  for (const k of ["label", "address", "policeStation"]) if (b[k] !== undefined) patch[k] = b[k];
  if (b.rooms) patch.rooms = toRooms(b.rooms);
  await fbPatch(env, "properties/" + pid, patch);
  return json({ ok: true });
}

async function createTenant(request, env, u) {
  const b = await request.json();
  for (const k of ["pid", "roomNo", "name", "parentage", "dob", "permAddr"]) if (!b[k]) throw err(400, k + " required");
  const P = await fbGet(env, "properties/" + b.pid);
  if (!P || P.lid !== u.lid) throw err(404, "property not found");

  const tid = id("T");
  const cardNo = await nextCardNo(env);
  const days = Number(b.validDays || env.DEFAULT_VALID_DAYS || 365);
  const now = Date.now();
  const customTill = Number(b.validTill || 0);                // explicit expiry (ms) wins over validDays
  if (customTill && customTill < now + 86400000) throw err(400, "Valid-till date must be in the future");
  const T = {
    lid: u.lid, pid: b.pid, roomNo: String(b.roomNo),
    name: b.name, parentage: b.parentage, dob: b.dob, permAddr: b.permAddr,
    phone: b.phone || "", emergency: b.emergency || "",
    idDocType: b.idDocType || "", idDocLast4: (b.idDocLast4 || "").slice(-4),
    cardNo, tokenVer: 1, status: b.activate === false ? "pending" : "active",
    issuedAt: now, validTill: customTill || now + days * 86400000,
    photo: null, vault: [], createdAt: now, createdBy: u.actingAdmin ? "admin" : "landlord"
  };
  await fbPut(env, "tenants/" + tid, T);
  await fbPut(env, "feed/" + u.lid + "/" + id("F"), { type: "card", at: now, tid, cardNo, name: T.name, roomNo: T.roomNo, action: "created" });
  await fbPut(env, "cards/" + cardNo, { tid });
  const token = await cardToken(env, tid, 1);
  return json({ ok: true, tid, cardNo, token, qrUrl: env.BASE_URL + "/v/" + token, tenant: T });
}

async function patchTenant(request, env, u, tid) {
  const T = await ownTenant(env, u, tid);
  const b = await request.json();
  const now = Date.now();
  const patch = {};
  switch (b.action) {
    case "revoke":   // tenant left
      patch.status = "revoked"; patch.revokedAt = now; patch.revokeReason = b.reason || "Tenant left the room";
      patch.vacateChecklist = b.checklist || null; break;
    case "lost":     // card lost → kill old QR, keep tenant active, new token
      patch.status = "active"; patch.tokenVer = (T.tokenVer || 1) + 1; patch.lostAt = now; break;
    case "reissue":  // new QR, same tenant
      patch.tokenVer = (T.tokenVer || 1) + 1; patch.reissuedAt = now; break;
    case "renew":
      patch.status = "active"; patch.validTill = Number(b.validTill) > now ? Number(b.validTill) : now + Number(b.validDays || env.DEFAULT_VALID_DAYS) * 86400000;
      patch.revokedAt = null; patch.revokeReason = null; break;
    case "validity":   // change expiry only; keeps status (an expired card becomes active again if the new date is in the future)
      if (!(Number(b.validTill) > now)) throw err(400, "Valid-till date must be in the future");
      patch.validTill = Number(b.validTill); if (T.status !== "revoked" && T.status !== "pending") patch.status = "active"; break;
    case "activate": patch.status = "active"; break;
    case "update":
      for (const k of ["roomNo", "name", "parentage", "dob", "permAddr", "phone", "emergency", "idDocType", "idDocLast4", "validTill"])
        if (b[k] !== undefined) patch[k] = k === "idDocLast4" ? String(b[k]).slice(-4) : b[k];
      break;
    default: throw err(400, "unknown action");
  }
  await fbPatch(env, "tenants/" + tid, patch);
  if (b.action !== "update") await fbPut(env, "feed/" + u.lid + "/" + id("F"), { type: "card", at: now, tid, cardNo: T.cardNo, name: T.name, roomNo: T.roomNo, action: b.action });
  const ver = patch.tokenVer || T.tokenVer || 1;
  const token = await cardToken(env, tid, ver);
  return json({ ok: true, token, qrUrl: env.BASE_URL + "/v/" + token });
}

async function uploadPhoto(request, env, u, tid) {
  await ownTenant(env, u, tid);
  const form = await request.formData();
  const f = form.get("file"); if (!f || typeof f === "string") throw err(400, "multipart field 'file' required");
  const thumb = String(form.get("thumb") || "");                     // tiny base64 JPEG made by the app → instant list thumbnails
  const tg = await tgUpload(env, f, `photo ${tid}`);
  const patch = { photo: tg }; if (thumb.startsWith("data:image/jpeg;base64,") && thumb.length < 16000) patch.thumb = thumb;
  await fbPatch(env, "tenants/" + tid, patch);
  return json({ ok: true, photo: tg });
}

/* ---- card appearance defaults; landlord can override in the app (More → Card settings) ---- */
const CARD_DEFAULTS = {
  title: "IDENTITY CARD",
  issuedBy: "Issued by {landlord} (Landlord) · {address}",
  instructions: "Return this card when vacating · Non-transferable · Validity is checked live by QR — a cancelled card scans NOT VALID",
  watermark: "{landlord} · VERIFY BY QR",
  found: "If found, please return to the landlord or {police}",
  design: "B"
};
function maskedId(type, last4) {
  if (!last4) return "—"; const t = String(type || "").toLowerCase();
  if (t.includes("aadh")) return "XXXX XXXX " + last4;
  if (t.includes("pass")) return "XXXX" + last4;
  return "XXXXXX" + last4;
}
function cardSettings(env, L, P) {
  const c = { ...CARD_DEFAULTS, ...((L && L.card) || {}) };
  const fill = v => String(v || "").replace(/\{landlord\}/g, (L && L.name) || "").replace(/\{address\}/g, (P && P.address) || "").replace(/\{property\}/g, (P && (P.label || P.address)) || "")
    .replace(/\{phone\}/g, (L && L.phone) || "").replace(/\{police\}/g, (P && P.policeStation) || "").replace(/\{site\}/g, String(env.BASE_URL || "").replace(/^https?:\/\//, ""));
  return { design: ["A", "B", "C", "D", "E"].includes(c.design) ? c.design : "B", title: fill(c.title), issuedBy: fill(c.issuedBy), instructions: fill(c.instructions), watermark: fill(c.watermark), found: fill(c.found || CARD_DEFAULTS.found).replace(/\s+$/, "") || "If found, please return to the nearest police station", helpline: String((L && L.helpline) || "").trim() };
}

async function uploadPropertyLogo(request, env, u, pid) {
  const P = await fbGet(env, "properties/" + pid);
  if (!P || P.lid !== u.lid) throw err(404, "property not found");
  const f = await getFile(request);
  const tg = await tgUpload(env, f, `logo ${pid}`);
  await fbPatch(env, "properties/" + pid, { logo: tg });
  return json({ ok: true, logo: tg });
}
async function publicLogo(env, token) {
  const r = await resolveToken(env, token);
  if (!r.P || !r.P.logo) throw err(404, "no logo");
  return tgServe(env, r.P.logo.file_id, r.P.logo.mime);
}

// kind = "signature" | "seal" — transparent PNGs the app composites onto the card
async function uploadLandlordImage(request, env, u, kind) {
  const f = await getFile(request);
  if (!/png/i.test(f.type || "") && !/\.png$/i.test(f.name || "")) throw err(400, kind + " must be a transparent PNG");
  const tg = await tgUpload(env, f, `${kind} ${u.lid}`);
  await fbPatch(env, "landlords/" + u.lid, { [kind]: tg });
  return json({ ok: true, [kind]: tg });
}

// public: signature/seal shown on the verify page, keyed by a valid card token (not guessable)
async function publicStamp(env, token, kind) {
  const r = await resolveToken(env, token);
  if (!r.L || !r.L[kind]) throw err(404, "no " + kind);
  return tgServe(env, r.L[kind].file_id, "image/png");
}

async function landlordImage(env, u, kind) {
  if (kind !== "signature" && kind !== "seal") throw err(404, "not found");
  const L = await fbGet(env, "landlords/" + u.lid);
  if (!L || !L[kind]) throw err(404, "no " + kind + " uploaded");
  return tgServe(env, L[kind].file_id, "image/png");
}

async function uploadVault(request, env, u, tid) {
  const T = await ownTenant(env, u, tid);
  const form = await request.formData();
  const f = form.get("file");
  if (!f || typeof f === "string") throw err(400, "file required");
  const label = String(form.get("label") || f.name || "document");
  const tg = await tgUpload(env, f, `vault ${tid} ${label}`);
  const vault = (T.vault || []).concat([{ ...tg, label, at: Date.now() }]);
  await fbPatch(env, "tenants/" + tid, { vault });
  return json({ ok: true, index: vault.length - 1, vault });
}

async function deleteVault(env, u, tid, idx) {
  const T = await ownTenant(env, u, tid);
  const vault = (T.vault || []).slice();
  if (!vault[idx]) throw err(404, "no such document");
  vault.splice(Number(idx), 1);
  await fbPatch(env, "tenants/" + tid, { vault });
  return json({ ok: true, vault });
}

async function listVault(env, u, tid) {
  const T = await ownTenant(env, u, tid);
  return json({ ok: true, vault: await signedVault(env, tid, T.vault || []) });
}

async function tenantLogs(env, u, tid) {
  await ownTenant(env, u, tid);
  const [scans, notes] = await Promise.all([fbGet(env, "scans/" + tid), fbGet(env, "notes/" + tid)]);
  return json({ ok: true, scans: scans || {}, notes: notes || {} });
}

async function createViewer(request, env, u) {
  const b = await request.json();
  for (const k of ["name", "dept", "loginId", "pin"]) if (!b[k]) throw err(400, k + " required");
  const loginId = String(b.loginId).toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (Object.keys(await fbQuery(env, "viewers", "loginId", loginId)).length) throw err(409, "loginId taken");
  const { hash, salt } = await hashPin(b.pin);
  const vid = id("V");
  await fbPut(env, "viewers/" + vid, {
    lid: u.lid, name: b.name, dept: b.dept, badgeNo: b.badgeNo || "", station: b.station || "",
    loginId, pinHash: hash, pinSalt: salt,
    perms: { vault: !!b.perms?.vault, note: !!b.perms?.note, history: !!b.perms?.history },
    expiresAt: b.expiresAt || null, status: "active", createdAt: Date.now()
  });
  return json({ ok: true, vid, loginId });
}

async function patchViewer(request, env, u, vid) {
  const V = await fbGet(env, "viewers/" + vid);
  if (!V || V.lid !== u.lid) throw err(404, "viewer not found");
  const b = await request.json();
  const patch = {};
  for (const k of ["name", "dept", "badgeNo", "station", "status", "expiresAt"]) if (b[k] !== undefined) patch[k] = b[k];
  if (b.perms) patch.perms = { vault: !!b.perms.vault, note: !!b.perms.note, history: !!b.perms.history };
  if (b.pin) { const { hash, salt } = await hashPin(b.pin); patch.pinHash = hash; patch.pinSalt = salt; }
  await fbPatch(env, "viewers/" + vid, patch);
  return json({ ok: true });
}

async function patchMe(request, env, u) {
  const b = await request.json();
  const patch = {};
  if (b.name) patch.name = String(b.name);
  if (b.tgChatId !== undefined) patch.tgChatId = String(b.tgChatId || "");
  if (b.alerts) patch.alerts = { scan: !!b.alerts.scan, note: !!b.alerts.note };
  if (b.helpline !== undefined) patch.helpline = String(b.helpline || "");
  if (b.card && typeof b.card === "object") { const c = {}; for (const k of ["title", "issuedBy", "instructions", "watermark", "found", "design"]) if (b.card[k] !== undefined) c[k] = String(b.card[k] || "").slice(0, 220); patch.card = { ...((await fbGet(env, "landlords/" + u.lid + "/card")) || {}), ...c }; }
  await fbPatch(env, "landlords/" + u.lid, patch);
  return json({ ok: true });
}

async function changePin(request, env, u) {
  const { oldPin, newPin } = await request.json();
  const L = await fbGet(env, "landlords/" + u.lid);
  if (!u.actingAdmin && !(await verifyPin(oldPin || "", L.pinHash, L.pinSalt))) throw err(401, "Current password is wrong");
  if (!newPin || String(newPin).length < 4) throw err(400, "New password must be at least 4 characters");
  const { hash, salt } = await hashPin(newPin);
  await fbPatch(env, "landlords/" + u.lid, { pinHash: hash, pinSalt: salt });
  return json({ ok: true });
}

async function deleteProperty(env, u, pid) {
  const P = await fbGet(env, "properties/" + pid);
  if (!P || P.lid !== u.lid) throw err(404, "property not found");
  const ts = await fbQuery(env, "tenants", "pid", pid);
  if (Object.keys(ts).length) throw err(409, "Property has tenants — remove their cards first");
  await fbDelete(env, "properties/" + pid);
  return json({ ok: true });
}

async function deleteViewer(env, u, vid) {
  const V = await fbGet(env, "viewers/" + vid);
  if (!V || V.lid !== u.lid) throw err(404, "viewer not found");
  await fbDelete(env, "viewers/" + vid);
  return json({ ok: true });
}

async function withLinks(env, rows) {
  for (const tid in rows) {
    const T = rows[tid];
    const token = await cardToken(env, tid, T.tokenVer || 1);
    T.token = token; T.qrUrl = env.BASE_URL + "/v/" + token; T.photoUrl = T.photo ? env.BASE_URL + "/photo/" + token + ver(T.photo) : null;
  }
  return rows;
}

/** Rooms with occupancy for every property of this landlord. */
async function roomsData(env, u) {
  const [props, tenants] = await Promise.all([fbQuery(env, "properties", "lid", u.lid), fbQuery(env, "tenants", "lid", u.lid)]);
  const out = [];
  for (const pid in props) {
    const P = props[pid];
    const rooms = {};
    for (const no of Object.keys(P.rooms || {})) rooms[no] = { no, tenants: [], lastVacatedAt: 0 };
    for (const tid in tenants) {
      const T = tenants[tid]; if (T.pid !== pid) continue;
      const no = String(T.roomNo); if (!rooms[no]) rooms[no] = { no, tenants: [], lastVacatedAt: 0, unlisted: true };
      const st = effStatus(T);
      if (st === "active" || st === "pending" || st === "expired") rooms[no].tenants.push({ tid, name: T.name, status: st, cardNo: T.cardNo, validTill: T.validTill });
      else if (st === "revoked") rooms[no].lastVacatedAt = Math.max(rooms[no].lastVacatedAt, T.revokedAt || 0);
    }
    const list = Object.values(rooms).sort((a, b) => a.no.localeCompare(b.no, undefined, { numeric: true }));
    out.push({ pid, label: P.label || "", address: P.address, policeStation: P.policeStation || "", rooms: list,
      occupied: list.filter(r => r.tenants.length).length, total: list.length });
  }
  return out;
}
async function rooms(env, u) { return json({ ok: true, properties: await roomsData(env, u) }); }

async function dashboard(env, u) {
  const [L, tenants, props, feed] = await Promise.all([
    fbGet(env, "landlords/" + u.lid), fbQuery(env, "tenants", "lid", u.lid), roomsData(env, u),
    fbGet(env, "feed/" + u.lid, { orderBy: '"at"', limitToLast: 40 })
  ]);
  const now = Date.now(), day = 86400000;
  const c = { tenants: 0, active: 0, pending: 0, expired: 0, revoked: 0, expiringSoon: [] , noPhoto: 0 };
  for (const tid in tenants) {
    const T = tenants[tid]; c.tenants++; const st = effStatus(T); c[st] = (c[st] || 0) + 1;
    if (st === "active" && T.validTill - now < 30 * day) c.expiringSoon.push({ tid, name: T.name, roomNo: T.roomNo, validTill: T.validTill, cardNo: T.cardNo });
    if (st === "active" && !T.photo) c.noPhoto++;
  }
  let scans24 = 0, notes7 = 0, invalid24 = 0;
  const items = Object.values(feed || {}).sort((a, b) => b.at - a.at);
  for (const f of items) { if (f.type === "scan" && now - f.at < day) { scans24++; if (f.result !== "valid") invalid24++; } if (f.type === "note" && now - f.at < 7 * day) notes7++; }
  const roomsTotal = props.reduce((n, p) => n + p.total, 0), roomsOcc = props.reduce((n, p) => n + p.occupied, 0);
  return json({ ok: true, name: L.name, actingAdmin: !!u.actingAdmin, counts: c, scans24, invalid24, notes7, roomsTotal, roomsOcc, properties: props.length,
    hasSignature: !!L.signature, hasSeal: !!L.seal, tgLinked: !!L.tgChatId, recent: items.slice(0, 15) });
}

async function exportCsv(env, u, tid) {
  const tenants = tid ? { [tid]: await ownTenant(env, u, tid) } : await fbQuery(env, "tenants", "lid", u.lid);
  const rows = [["type", "card_no", "tenant", "room", "time", "result_or_tag", "by", "department", "city", "text_or_scan_id"]];
  const q = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
  for (const id0 in tenants) {
    const T = tenants[id0];
    const [scans, notes] = await Promise.all([fbGet(env, "scans/" + id0), fbGet(env, "notes/" + id0)]);
    for (const k in (scans || {})) { const s = scans[k]; rows.push(["scan", T.cardNo, T.name, T.roomNo, new Date(s.at).toISOString(), s.result, s.by === "public" ? "public" : s.byName, s.dept, s.city, s.scanId]); }
    for (const k in (notes || {})) { const n = notes[k]; rows.push(["note", T.cardNo, T.name, T.roomNo, new Date(n.at).toISOString(), n.tag, n.viewerName, n.dept, "", n.text]); }
  }
  rows.sort((a, b) => a[4] < b[4] ? 1 : -1);
  const csv = rows.map(r => r.map(q).join(",")).join("\r\n");
  return cors(new Response(csv, { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="tenant-logs${tid ? "-" + tid : ""}.csv"` } }));
}

/* ============================ VIEWER ============================ */

async function viewerScan(request, env, u) {
  let { token, cardNo, lat, lng } = await request.json();
  if (!token && cardNo) {                       // manual entry when QR is damaged
    const c = await fbGet(env, "cards/" + String(cardNo).trim().toUpperCase());
    if (!c) return json({ ok: true, result: "invalid", reason: "UNKNOWN_CARD" });
    const T0 = await fbGet(env, "tenants/" + c.tid);
    token = await cardToken(env, c.tid, T0.tokenVer || 1);
  }
  if (token && token.startsWith("http")) token = token.split("/v/")[1] || token;   // full QR URL pasted
  const r = await resolveToken(env, token);
  const scanId = await logScan(env, request, r, { by: u.vid, byName: u.name, dept: u.dept, lat, lng });
  if (!r.ok) return json({ ok: true, result: r.result, reason: r.reason, scanId, cardNo: r.T ? r.T.cardNo : null, name: r.T ? r.T.name : null, roomNo: r.T ? r.T.roomNo : null,
    revokedAt: r.T ? r.T.revokedAt || null : null, validTill: r.T ? r.T.validTill : null, photoUrl: r.T && r.T.photo ? env.BASE_URL + "/photo/" + token + ver(r.T.photo) : null });

  const { tid, T, P, L } = r;
  const own = T.lid === u.lid;                   // vault / notes / history only for the landlord who created this login
  const perms = own ? (u.perms || {}) : { vault: false, note: false, history: false };
  const out = {
    ok: true, result: "valid", scanId, tid, cardNo: T.cardNo, own,
    tenant: pick(T, ["name", "parentage", "dob", "permAddr", "phone", "emergency", "roomNo", "idDocType", "idDocLast4", "issuedAt", "validTill", "status"]),
    property: { address: P.address, policeStation: P.policeStation },
    landlord: { name: L.name, phone: L.phone },
    photoUrl: T.photo ? env.BASE_URL + "/photo/" + token + ver(T.photo) : null,
    sigUrl: L.signature ? env.BASE_URL + "/sig/" + token + ver(L.signature) : null,
    sealUrl: L.seal ? env.BASE_URL + "/seal/" + token + ver(L.seal) : null,
    perms
  };
  if (perms.vault) out.vault = await signedVault(env, tid, T.vault || []);
  if (perms.history) {
    const [scans, notes] = await Promise.all([fbGet(env, "scans/" + tid), fbGet(env, "notes/" + tid)]);
    out.scans = scans || {}; out.notes = notes || {};
  }
  return json(out);
}

/** Read-only list of the landlord's tenants for an official login (basic fields + thumbnail). */
async function viewerTenants(env, u) {
  const rows = await fbQuery(env, "tenants", "lid", u.lid);
  const props = await fbQuery(env, "properties", "lid", u.lid);
  const out = {};
  for (const tid in rows) { const T = rows[tid]; const P = props[T.pid] || {};
    out[tid] = { name: T.name, parentage: T.parentage, roomNo: T.roomNo, cardNo: T.cardNo, status: effStatus(T), thumb: T.thumb || null, address: P.address || "", pid: T.pid, createdAt: T.createdAt, validTill: T.validTill }; }
  return json({ ok: true, tenants: out, landlord: u.lid });
}

/** Full details opened from the list (same payload as a scan; logged as a "list view"). */
async function viewerTenant(request, env, u, tid) {
  const T = await fbGet(env, "tenants/" + tid);
  if (!T || T.lid !== u.lid) throw err(404, "tenant not found");
  const token = await cardToken(env, tid, T.tokenVer || 1);
  const r = await resolveToken(env, token);
  const scanId = await logScan(env, request, r, { by: u.vid, byName: u.name, dept: u.dept, via: "list" });
  const { P, L } = r; const perms = u.perms || {};
  const out = {
    ok: true, result: r.result, reason: r.reason || null, scanId, tid, cardNo: T.cardNo, own: true, viaList: true,
    tenant: pick(T, ["name", "parentage", "dob", "permAddr", "phone", "emergency", "roomNo", "idDocType", "idDocLast4", "issuedAt", "validTill", "status"]),
    property: { address: P.address, policeStation: P.policeStation }, landlord: { name: L.name, phone: L.phone },
    photoUrl: T.photo ? env.BASE_URL + "/photo/" + token + ver(T.photo) : null, sigUrl: L.signature ? env.BASE_URL + "/sig/" + token + ver(L.signature) : null, sealUrl: L.seal ? env.BASE_URL + "/seal/" + token + ver(L.seal) : null,
    revokedAt: T.revokedAt || null, perms
  };
  if (perms.vault) out.vault = await signedVault(env, tid, T.vault || []);
  if (perms.history) { const [scans, notes] = await Promise.all([fbGet(env, "scans/" + tid), fbGet(env, "notes/" + tid)]); out.scans = scans || {}; out.notes = notes || {}; }
  return json(out);
}

async function viewerNote(request, env, u) {
  if (!u.perms?.note) throw err(403, "notes not allowed for your login");
  const { tid, tag, text } = await request.json();
  const T = await fbGet(env, "tenants/" + tid);
  if (!T || T.lid !== u.lid) throw err(404, "tenant not found");
  const tags = ["DOC_NOT_CLEAR", "SUSPECTED_FAKE", "ADDRESS_MISMATCH", "PERSON_MISMATCH", "OTHER"];
  if (!tags.includes(tag)) throw err(400, "tag must be one of " + tags.join(","));
  const nid = id("N");
  const rec = { vid: u.vid, viewerName: u.name, dept: u.dept, tag, text: String(text || "").slice(0, 500), at: Date.now() };
  await fbPut(env, "notes/" + tid + "/" + nid, rec);
  await fbPut(env, "feed/" + T.lid + "/" + id("F"), { type: "note", at: rec.at, tid, cardNo: T.cardNo, name: T.name, roomNo: T.roomNo, by: u.vid, byName: u.name, dept: u.dept, tag, text: rec.text });
  const L = await fbGet(env, "landlords/" + T.lid);
  alertLandlord(env, L, `📝 Note on ${T.name} (Room ${T.roomNo}, ${T.cardNo})\n${tag.replace(/_/g, " ")} — ${u.name} (${u.dept})\n${rec.text}`, "note");
  return json({ ok: true, nid });
}

/* ============================ PUBLIC SCAN ============================ */

async function publicJson(request, env, ctx, token, url) {
  const r = await resolveToken(env, token);
  const scanId = await logScan(env, request, r, { by: "public", lat: url.searchParams.get("lat"), lng: url.searchParams.get("lng") });
  return json(publicPayload(env, r, token, scanId));
}

async function publicPage(request, env, ctx, token, url) {
  const r = await resolveToken(env, token);
  const scanId = await logScan(env, request, r, { by: "public" });
  return html(verifyPage(env, publicPayload(env, r, token, scanId), token));
}

function publicPayload(env, r, token, scanId) {
  const base = { ok: true, result: r.result, reason: r.reason || null, scanId, at: Date.now() };
  if (!r.T) return base;                          // bad signature / unknown card
  const { T, P, L } = r;
  return {
    ...base,
    cardNo: T.cardNo, name: T.name, parentage: T.parentage, dob: T.dob,
    roomNo: T.roomNo, roomAddr: P.address, permAddr: T.permAddr,
    policeStation: P.policeStation, landlord: L.name, landlordPhone: L.phone || "", mobile: T.phone || "",
    idDocType: T.idDocType || "ID DOCUMENT", idDoc: maskedId(T.idDocType, T.idDocLast4),
    issuedAt: T.issuedAt, validTill: T.validTill, revokedAt: T.revokedAt || null,
    card: cardSettings(env, L, P),
    logoUrl: P.logo ? env.BASE_URL + "/logo/" + token + ver(P.logo) : null,
    photoUrl: T.photo ? env.BASE_URL + "/photo/" + token + ver(T.photo) : null,
    sigUrl: L.signature ? env.BASE_URL + "/sig/" + token + ver(L.signature) : null,
    sealUrl: L.seal ? env.BASE_URL + "/seal/" + token + ver(L.seal) : null
  };
}

async function publicPhoto(env, token) {
  const r = await resolveToken(env, token);
  if (!r.T || !r.T.photo) throw err(404, "no photo");
  return tgServe(env, r.T.photo.file_id, r.T.photo.mime);
}

async function vaultFile(env, tid, idx, url) {
  const exp = Number(url.searchParams.get("exp") || 0);
  const sig = url.searchParams.get("sig") || "";
  if (Date.now() > exp) throw err(410, "link expired");
  if (sig !== await hmac(env, `vault|${tid}|${idx}|${exp}`)) throw err(403, "bad signature");
  const T = await fbGet(env, "tenants/" + tid);
  const d = T && (T.vault || [])[idx];
  if (!d) throw err(404, "document not found");
  return tgServe(env, d.file_id, d.mime, d.name);
}

async function cardLookup(env, cardNo) {
  const c = await fbGet(env, "cards/" + cardNo.toUpperCase());
  if (!c) throw err(404, "card not found");
  const T = await fbGet(env, "tenants/" + c.tid);
  const token = await cardToken(env, c.tid, T.tokenVer || 1);
  return Response.redirect(env.BASE_URL + "/v/" + token, 302);
}

/* ============================ CORE LOGIC ============================ */

async function resolveToken(env, token) {
  const parsed = await parseCardToken(env, token);
  if (!parsed) return { ok: false, result: "invalid", reason: "FAKE_OR_DAMAGED" };
  const T = await fbGet(env, "tenants/" + parsed.tid);
  if (!T) return { ok: false, result: "invalid", reason: "UNKNOWN_CARD" };
  const [P, L] = await Promise.all([fbGet(env, "properties/" + T.pid), fbGet(env, "landlords/" + T.lid)]);
  const base = { tid: parsed.tid, T, P: P || {}, L: L || {} };
  if (parsed.ver !== (T.tokenVer || 1)) return { ...base, ok: false, result: "invalid", reason: "CARD_REISSUED" };
  const s = effStatus(T);
  if (s === "active") return { ...base, ok: true, result: "valid" };
  const reason = { revoked: "TENANT_LEFT", expired: "VALIDITY_ENDED", pending: "NOT_ACTIVATED" }[s] || "INVALID";
  return { ...base, ok: false, result: s === "pending" ? "pending" : "invalid", reason };
}

function effStatus(T) {
  if (T.status === "revoked" || T.status === "pending") return T.status;
  if (T.validTill && Date.now() > T.validTill) return "expired";
  return "active";
}
function withStatus(rows) { for (const k in rows) rows[k].effStatus = effStatus(rows[k]); return rows; }

async function logScan(env, request, r, extra) {
  const scanId = Math.random().toString(36).slice(2, 8).toUpperCase();
  const cf = request.cf || {};
  const rec = {
    scanId, at: Date.now(), result: r.result, reason: r.reason || null,
    by: extra.by, byName: extra.byName || null, dept: extra.dept || null, via: extra.via || "scan",
    ip: request.headers.get("CF-Connecting-IP") || null,
    city: cf.city || null, region: cf.region || null, country: cf.country || null,
    lat: extra.lat ? Number(extra.lat) : (cf.latitude ? Number(cf.latitude) : null),
    lng: extra.lng ? Number(extra.lng) : (cf.longitude ? Number(cf.longitude) : null),
    ua: (request.headers.get("User-Agent") || "").slice(0, 120)
  };
  if (r.tid) {
    await fbPut(env, "scans/" + r.tid + "/" + id("S"), rec);
    if (extra.by && extra.by !== "public") await fbPut(env, "viewerScans/" + extra.by + "/" + id("S"), { ...rec, tid: r.tid, cardNo: r.T?.cardNo, name: r.T?.name, roomNo: r.T?.roomNo });
    const f = { type: "scan", via: rec.via, at: rec.at, tid: r.tid, cardNo: r.T?.cardNo, name: r.T?.name, roomNo: r.T?.roomNo, result: rec.result, reason: rec.reason, by: rec.by, byName: rec.byName, dept: rec.dept, city: rec.city, scanId };
    await fbPut(env, "feed/" + r.T.lid + "/" + id("F"), f);
    await fbPut(env, "adminFeed/" + id("F"), { ...f, lid: r.T.lid });
    const who = rec.by === "public" ? "Public scan" : `${rec.byName} (${rec.dept})${rec.via === "list" ? " viewed from list" : ""}`;
    alertLandlord(env, r.L, `${rec.result === "valid" ? "✅" : "❌"} ${rec.result.toUpperCase()} — ${r.T.name} (Room ${r.T.roomNo}, ${r.T.cardNo})\n${who}${rec.city ? " · " + rec.city : ""} · #${scanId}`, "scan");
  } else {
    await fbPut(env, "badScans/" + id("S"), rec);
  }
  return scanId;
}

/** Telegram message to the landlord's own chat (if they set it in Settings). Fire-and-forget. */
function alertLandlord(env, L, text, kind) {
  try {
    if (!L || !L.tgChatId) return;
    const a = L.alerts || { scan: true, note: true };
    if (a[kind] === false) return;
    const p = fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: L.tgChatId, text, disable_web_page_preview: true }) }).catch(() => {});
    if (CTX && CTX.waitUntil) CTX.waitUntil(p);
  } catch (e) {}
}

async function ownTenant(env, u, tid) {
  const T = await fbGet(env, "tenants/" + tid);
  if (!T || T.lid !== u.lid) throw err(404, "tenant not found");
  return T;
}

async function signedVault(env, tid, vault) {
  const ttl = Number(env.VAULT_LINK_TTL || 300) * 1000;
  const out = [];
  for (let i = 0; i < vault.length; i++) {
    const exp = Date.now() + ttl;
    const sig = await hmac(env, `vault|${tid}|${i}|${exp}`);
    out.push({ index: i, label: vault[i].label, name: vault[i].name, mime: vault[i].mime, size: vault[i].size, at: vault[i].at,
      url: `${env.BASE_URL}/vault/${tid}/${i}?exp=${exp}&sig=${sig}` });
  }
  return out;
}

async function nextCardNo(env) {
  const year = new Date().getFullYear();
  for (let i = 0; i < 5; i++) {
    const res = await fetch(fbUrl(env, "counters/cardSeq"), { headers: { "X-Firebase-ETag": "true" } });
    const etag = res.headers.get("ETag");
    const cur = Number(await res.json()) || 0;
    const put = await fetch(fbUrl(env, "counters/cardSeq"), { method: "PUT", headers: { "if-match": etag }, body: String(cur + 1) });
    if (put.ok) return `${env.CARD_PREFIX || "TNT"}-${year}-${String(cur + 1).padStart(6, "0")}`;
  }
  throw err(500, "card counter busy, retry");
}

/* ============================ TELEGRAM STORAGE ============================ */

async function tgUpload(env, file, caption) {
  const fd = new FormData();
  fd.append("chat_id", env.TG_CHAT_ID);
  fd.append("caption", caption.slice(0, 200));
  fd.append("disable_notification", "true");
  fd.append("document", file, file.name || "file");
  const r = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendDocument`, { method: "POST", body: fd });
  const j = await r.json();
  if (!j.ok) throw err(502, "telegram upload failed: " + (j.description || ""));
  const d = j.result.document;
  return { file_id: d.file_id, name: d.file_name || file.name || "file", mime: d.mime_type || file.type || "application/octet-stream", size: d.file_size || file.size || 0, msg: j.result.message_id, at: Date.now() };
}
/** Cache-busting query for an image URL: changes whenever the stored file changes. */
function ver(f) { return "?v=" + (f && (f.at || f.msg) ? String(f.at || f.msg) : "0"); }

/** Serves a Telegram-stored file. Bytes are cached at the Cloudflare edge for a day (keyed by file_id), so repeat loads skip Telegram entirely. */
async function tgServe(env, fileId, mime, name) {
  const h = new Headers({ "Content-Type": mime || "application/octet-stream", "Cache-Control": "private, max-age=86400, immutable", "X-Content-Type-Options": "nosniff" });
  if (name) h.set("Content-Disposition", `inline; filename="${name.replace(/"/g, "")}"`);
  let cache = null, key = null;
  try { cache = caches.default; key = new Request("https://tg-cache.internal/" + encodeURIComponent(fileId)); const hit = await cache.match(key); if (hit) return cors(new Response(hit.body, { status: 200, headers: h })); } catch (e) { cache = null; }
  const r = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
  const j = await r.json();
  if (!j.ok) throw err(502, "telegram getFile failed");
  const f = await fetch(`https://api.telegram.org/file/bot${env.TG_BOT_TOKEN}/${j.result.file_path}`);
  if (!f.ok) throw err(502, "telegram download failed");
  const buf = await f.arrayBuffer();
  if (cache) { try { const p = cache.put(key, new Response(buf.slice(0), { headers: { "Content-Type": mime || "application/octet-stream", "Cache-Control": "public, max-age=86400" } })); if (CTX && CTX.waitUntil) CTX.waitUntil(p); } catch (e) {} }
  return cors(new Response(buf, { status: 200, headers: h }));
}

async function getFile(request) {
  const form = await request.formData();
  const f = form.get("file");
  if (!f || typeof f === "string") throw err(400, "multipart field 'file' required");
  return f;
}

/* ============================ FIREBASE REST ============================ */

function fbUrl(env, path, q) {
  const u = new URL(`${env.FB_DB_URL.replace(/\/$/, "")}/${path}.json`);
  u.searchParams.set("auth", env.FB_SECRET);
  for (const k in q || {}) u.searchParams.set(k, q[k]);
  return u.toString();
}
async function fbGet(env, path, q) { const r = await fetch(fbUrl(env, path, q)); const j = await r.json(); if (!r.ok) throw fbErr(r, j); return j; }
async function fbPut(env, path, body) { const r = await fetch(fbUrl(env, path), { method: "PUT", body: JSON.stringify(body) }); if (!r.ok) throw fbErr(r, await r.json().catch(() => ({}))); }
async function fbPatch(env, path, body) { const r = await fetch(fbUrl(env, path), { method: "PATCH", body: JSON.stringify(body) }); if (!r.ok) throw fbErr(r, await r.json().catch(() => ({}))); }
function fbErr(r, j) {
  const m = String((j && j.error) || r.status);
  if (/index/i.test(m)) return err(500, "Firebase index missing — paste firebase.rules.json into Firebase → Realtime Database → Rules → Publish");
  if (/permission/i.test(m) || r.status === 401) return err(500, "Firebase rejected the database secret — check FB_SECRET and FB_DB_URL");
  return err(500, "Firebase: " + m);
}
async function fbDelete(env, path) { const r = await fetch(fbUrl(env, path), { method: "DELETE" }); if (!r.ok) throw fbErr(r, await r.json().catch(() => ({}))); }
async function fbQuery(env, path, key, val) { return (await fbGet(env, path, { orderBy: JSON.stringify(key), equalTo: JSON.stringify(val) })) || {}; }

/* ============================ CRYPTO ============================ */

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));
const unb64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return atob(s); };

async function hmac(env, data, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret || env.HMAC_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}

async function cardToken(env, tid, ver) {
  const body = b64uStr(`${tid}.${ver}`);
  return body + "." + (await hmac(env, body)).slice(0, 22);
}
async function parseCardToken(env, token) {
  if (!token || token.length > 200) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  if (sig !== (await hmac(env, body)).slice(0, 22)) return null;
  const [tid, ver] = unb64u(body).split(".");
  return { tid, ver: Number(ver) };
}

async function jwtSign(env, payload, ttlSec) {
  const h = b64uStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64uStr(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + ttlSec }));
  return `${h}.${p}.${await hmac(env, `${h}.${p}`, env.JWT_SECRET)}`;
}
async function jwtVerify(env, token) {
  const [h, p, s] = (token || "").split(".");
  if (!h || !p || !s) return null;
  if (s !== await hmac(env, `${h}.${p}`, env.JWT_SECRET)) return null;
  const payload = JSON.parse(unb64u(p));
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

async function hashPin(pin) {
  const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
  return { hash: await pbkdf2(String(pin), salt), salt };
}
async function verifyPin(pin, hash, salt) { return !!hash && (await pbkdf2(String(pin), salt)) === hash; }
async function pbkdf2(pin, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  return b64u(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, key, 256));
}

/* ============================ HELPERS ============================ */

function id(prefix) { return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function err(status, message) { const e = new Error(message); e.status = status; return e; }
function pick(o, keys) { const r = {}; for (const k of keys) if (o[k] !== undefined) r[k] = o[k]; return r; }
function strip1(v) { if (!v) return v; const { pinHash, pinSalt, ...rest } = v; return rest; }
function strip(rows) { const o = {}; for (const k in rows) o[k] = strip1(rows[k]); return o; }
function toRooms(rooms) { const o = {}; (Array.isArray(rooms) ? rooms : []).forEach(r => o[String(r)] = true); return o; }
function match(path, pattern) {
  const a = path.split("/"), b = pattern.split("/");
  if (a.length !== b.length) return null;
  const out = {};
  for (let i = 0; i < a.length; i++) {
    if (b[i].startsWith(":")) out[b[i].slice(1)] = decodeURIComponent(a[i]);
    else if (a[i] !== b[i]) return null;
  }
  return out;
}
function cors(res) {
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Admin-Key,X-HTTP-Method-Override");
  return res;
}
function json(obj, status = 200) { return cors(new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8" } })); }
function html(s, status = 200) { return new Response(s, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY" } }); }
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function fmtDate(ms) { if (!ms) return "—"; const d = new Date(ms); return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric", timeZone: "Asia/Kolkata" }); }

/* ============================ HTML PAGES ============================ */

function landing(env) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(env.APP_NAME)}</title>
<style>body{margin:0;font-family:Inter,system-ui,sans-serif;background:#F2F4F7;color:#141413;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
.c{background:#fff;border-radius:16px;padding:28px;max-width:420px;border:1px solid #D9DEE7}h1{font-size:20px;margin:0 0 8px}p{color:#5A6478;font-size:14px;line-height:1.5}
form{display:flex;gap:8px;margin-top:16px}input{flex:1;padding:12px;border:1px solid #D9DEE7;border-radius:10px;font-size:14px}button{padding:12px 16px;border:0;border-radius:10px;background:#1B3A6B;color:#fff;font-weight:700}</style></head>
<body><div class="c"><h1>${esc(env.APP_NAME)}</h1><p>Scan the QR on a tenant card with any camera to verify it live. If the QR is damaged, enter the card number printed on it.</p>
<form onsubmit="location.href='/c/'+encodeURIComponent(this.n.value.trim());return false"><input name="n" placeholder="TNT-2026-000123" required><button>Verify</button></form></div></body></html>`;
}

function verifyPage(env, d, token) {
  const valid = d.result === "valid";
  const pending = d.result === "pending";
  const col = valid ? "#0F5C4A" : pending ? "#8A4B08" : "#8E1F2B";
  const bg = valid ? "#DDF3E8" : pending ? "#FFF4E5" : "#F7DCDF";
  const word = valid ? "VALID" : pending ? "PENDING" : "NOT VALID";
  const reasonText = {
    TENANT_LEFT: "Tenant left the room · card cancelled " + fmtDate(d.revokedAt),
    VALIDITY_ENDED: "Validity ended on " + fmtDate(d.validTill),
    CARD_REISSUED: "This card was reported lost / re-issued",
    NOT_ACTIVATED: "Card not yet activated by landlord",
    FAKE_OR_DAMAGED: "This QR code is not genuine, or it is damaged",
    UNKNOWN_CARD: "No card found for this code"
  }[d.reason] || (valid ? "Active tenant · verified live just now" : "");
  const c = d.card || {};
  const seed = hashSeed(d.cardNo || "x");
  const rot = (base, spread, i) => (base + ((seed >> (i * 5)) % 100) / 100 * spread).toFixed(1);

  const isD = (c.design || "B") === "D", isE = (c.design || "B") === "E";
  const card = d.cardNo ? `
<div class="card d${esc(c.design || "B")} ${valid ? "" : "dim"}">
  <div class="wmk" aria-hidden="true">${Array(7).fill(`<div>${esc(c.watermark || "")} &nbsp;·&nbsp; ${esc(c.watermark || "")} &nbsp;·&nbsp; ${esc(c.watermark || "")}</div>`).join("")}</div>
  ${["B", "D", "E"].includes(c.design || "B") ? `<div class="tri"><i></i><i></i><i></i></div>` : ""}
  <div class="hd">
    <div class="logo">${d.logoUrl ? `<img src="${esc(d.logoUrl)}" alt="">` : `<img src="/logo.png" alt="" onerror="this.parentNode.innerHTML='<b style=color:#1B3A6B;font-size:14px>ID</b>'">`}</div>
    <div class="hdt"><div class="t1">${esc(c.title || "IDENTITY CARD")}</div><div class="t2">${esc(c.issuedBy || "")}</div></div>
    <div class="room"><div class="rl">ROOM</div><div class="rn">${esc(d.roomNo)}</div></div>
  </div>
  <div class="gband"></div>
  <div class="bd">
    <div class="lcol">
      <div class="phw">
        <div class="ph">${d.photoUrl ? `<img src="${esc(d.photoUrl)}" alt="Tenant photo">` : `<span>PHOTO</span>`}</div>
        ${d.sigUrl ? `<img class="stp sig1" style="transform:rotate(${rot(-11, 6, 1)}deg)" src="${esc(d.sigUrl)}" alt="">` : ""}
        ${d.sealUrl ? `<img class="stp seal1" style="transform:rotate(${rot(-22, 10, 0)}deg)" src="${esc(d.sealUrl)}" alt="">` : ""}
      </div>
      <div class="cno"><label>CARD NO.</label><b>${esc(d.cardNo)}</b></div>
      ${isD ? `<div class="lsig"><label>ISSUING LANDLORD</label>${d.sigUrl ? `<img class="stp sig3" style="transform:rotate(${rot(-5, 5, 2)}deg)" src="${esc(d.sigUrl)}" alt="">` : ""}${d.sealUrl ? `<img class="stp seal3" style="transform:rotate(${rot(8, 10, 3)}deg)" src="${esc(d.sealUrl)}" alt="">` : ""}<b>${esc(d.landlord)}</b></div>` : ""}
    </div>
    <div class="f">
      <div><label>NAME</label><b class="nm">${esc(d.name)}</b></div>
      <div class="row"><div style="flex:1.4"><label>FATHER / HUSBAND</label><b>${esc(d.parentage)}</b></div><div><label>DATE OF BIRTH</label><b>${esc(d.dob)}</b></div></div>
      <div><label>PERMANENT ADDRESS</label><span>${esc(d.permAddr)}</span></div>
      <div class="row"><div><label>${esc((d.idDocType || "ID DOCUMENT").toUpperCase())}</label><b>${esc(d.idDoc || "—")}</b></div><div><label>MOBILE</label><b>${esc(d.mobile || "—")}</b></div></div>
      <div class="row"><div><label>ISSUED</label><b>${fmtDate(d.issuedAt)}</b></div><div><label>VALID TILL</label><b>${fmtDate(d.validTill)}</b></div></div>
      <div class="sep"></div>
      <div><label>${valid ? "ROOM ADDRESS" : "WAS REGISTERED AT"}</label><span>Room ${esc(d.roomNo)}, ${esc(d.roomAddr)}</span></div>
      <div class="row"><div><label>LANDLORD</label><b>${esc(d.landlord)}</b></div><div><label>LANDLORD MOBILE</label><b>${esc(d.landlordPhone || "—")}</b></div></div>
      <div><label>POLICE STATION</label><b>${esc(d.policeStation || "—")}</b></div>
    </div>
  </div>
  ${isD ? `<div class="qrw"><img src="${esc(env.BASE_URL)}/qr/${esc(token)}" alt="QR" width="132" height="132"><div><b>SCAN TO VERIFY</b><span>Live validity · authenticity</span></div></div>` : isE ? `<div class="qrw"><img src="${esc(env.BASE_URL)}/qr/${esc(token)}" alt="QR" width="132" height="132"><div class="sgw e">${d.sigUrl ? `<img class="stp sig2" style="transform:rotate(${rot(-5, 5, 2)}deg)" src="${esc(d.sigUrl)}" alt="">` : ""}${d.sealUrl ? `<img class="stp seal2" style="transform:rotate(${rot(8, 10, 3)}deg)" src="${esc(d.sealUrl)}" alt="">` : ""}<div class="sgname">${esc(d.landlord)}<small>LANDLORD</small></div></div></div>` : `<div class="sgw">
    ${d.sigUrl ? `<img class="stp sig2" style="transform:rotate(${rot(-6, 5, 2)}deg)" src="${esc(d.sigUrl)}" alt="Landlord signature">` : ""}
    ${d.sealUrl ? `<img class="stp seal2" style="transform:rotate(${rot(6, 10, 3)}deg)" src="${esc(d.sealUrl)}" alt="Landlord seal">` : ""}
    <div class="sgname">${esc(d.landlord)}</div>
  </div>`}
  <div class="ft">${esc(c.instructions || "")}</div>
  <div class="fs">${esc(c.found || "")}${c.helpline ? " &nbsp;·&nbsp; Helpline " + esc(c.helpline) : ""}</div>
</div>` : `<div class="card dim"><div class="f" style="padding:14px"><b>No card data</b><span>${esc(reasonText)}</span></div></div>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>${word} · ${esc(env.APP_NAME)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--c:${col};--bg:${bg}}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:#141413;min-height:100vh;position:relative;overflow-x:hidden;-webkit-user-select:none;user-select:none}
.wm{position:fixed;inset:-40%;display:flex;flex-direction:column;gap:70px;transform:rotate(-32deg);color:var(--c);opacity:.11;font-weight:900;font-size:84px;letter-spacing:6px;white-space:nowrap;pointer-events:none;z-index:5;mix-blend-mode:multiply}
.band{position:fixed;left:0;right:0;top:0;height:6px;background:var(--c);animation:pulse 3s infinite;z-index:6}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.wrap{position:relative;z-index:1;max-width:430px;margin:0 auto;padding:22px 16px 24px;display:flex;flex-direction:column;gap:12px;min-height:100vh}
.st{display:flex;align-items:center;gap:12px;color:var(--c)}.st svg{width:40px;height:40px;flex-shrink:0}.st .w{font-size:30px;font-weight:900;letter-spacing:2px;line-height:1}.st .s{font-size:12px;font-weight:600;opacity:.85}
.card{position:relative;background:#fff;border-radius:16px;overflow:hidden;border:2px solid var(--c);box-shadow:0 8px 24px rgba(0,0,0,.12)}.card.dim{filter:grayscale(.6);opacity:.92}
.card .wmk{position:absolute;inset:-35%;display:flex;flex-direction:column;gap:34px;transform:rotate(-24deg);color:#1B3A6B;opacity:.07;font-size:20px;font-weight:800;letter-spacing:3px;white-space:nowrap;pointer-events:none;z-index:0}
.card .wmk div:nth-child(even){padding-left:90px}
.card>*:not(.wmk){position:relative;z-index:1}
.hd{background:#1B3A6B;color:#fff;padding:10px 12px;display:flex;align-items:center;gap:10px}
.tri{display:flex;height:6px}.tri i{flex:1}.tri i:nth-child(1){background:#F0862E}.tri i:nth-child(2){background:#fff}.tri i:nth-child(3){background:#159A5B}
.card.dB .hd,.card.dC .hd{background:#fff;color:#1B3A6B}.card.dC .hd{color:#141413}.card.dB .t2,.card.dC .t2{color:#5A6478;opacity:1}.card.dB .logo,.card.dC .logo{background:#EEF2F8}.card.dC .logo{border:1px solid #D9DEE7}
.card.dB .room{background:#1B3A6B;color:#fff}.card.dC .room{background:#F2F4F7;color:#1B3A6B;border:1.5px solid #1B3A6B}
.card.dB .gband,.card.dC .gband{background:#1B3A6B;height:3px}
.card.dB .fs,.card.dD .fs,.card.dE .fs{background:#159A5B}
.card.dE .hd{background:#fff;color:#1B3A6B}.card.dE .t2{color:#5A6478;opacity:1}.card.dE .logo{background:#EEF2F8}.card.dE .room{background:#1B3A6B;color:#fff}.card.dE .gband{background:#1B3A6B;height:3px}
.sgw.e{flex:1;height:96px;margin:0;position:relative}.sgw.e .sig2{right:48px;top:0}.sgw.e .seal2{right:-2px;top:-8px}.sgw.e .sgname{right:0;left:0;width:auto;bottom:0}.sgw.e .sgname small{display:block;font-size:8.5px;color:#5A6478;letter-spacing:1px}.card.dC .fs{background:#fff;color:#1B3A6B;border-top:2px solid #1B3A6B}
.card.dD .hd{background:#fff;color:#1B3A6B}.card.dD .t2{color:#5A6478;opacity:1}.card.dD .logo{background:#EEF2F8}.card.dD .room{background:#1B3A6B;color:#fff}.card.dD .gband{background:#1B3A6B;height:3px}
.sep{height:1px;background:#E3E8F0;margin:2px 0}.logo{width:44px;height:44px;border-radius:10px;background:#fff;flex-shrink:0;overflow:hidden;display:flex;align-items:center;justify-content:center}.logo img{width:100%;height:100%;object-fit:cover;aspect-ratio:1/1}
.gband{height:4px;background:#159A5B}
.hdt{flex:1;min-width:0}.t1{font-size:16px;font-weight:800;letter-spacing:2px}.t2{font-size:10px;opacity:.88;margin-top:2px;line-height:1.25}
.room{background:#fff;color:#1B3A6B;border-radius:9px;padding:5px 10px;text-align:center;line-height:1}.rl{font-size:7.5px;font-weight:800;letter-spacing:1.5px}.rn{font-size:21px;font-weight:900;margin-top:2px}
.bd{display:flex;gap:12px;padding:12px 12px 6px}.lcol{display:flex;flex-direction:column;gap:8px;flex-shrink:0;width:104px}.phw{position:relative;width:104px;height:124px}.ph{width:104px;height:124px;border-radius:8px;background:#F2F4F7;border:1px solid #D9DEE7;overflow:hidden;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#5A6478}.ph img{width:100%;height:100%;object-fit:cover}
.stp{position:absolute;pointer-events:none;object-fit:contain}.sig1{width:74px;height:28px;left:8px;bottom:8px;opacity:.95;z-index:1}.seal1{width:60px;height:60px;left:-22px;bottom:-14px;opacity:.84;z-index:2}
.lsig{position:relative;height:88px;text-align:center;padding-top:2px}.lsig label{display:block}.lsig b{position:absolute;left:0;right:0;bottom:0;font-size:11px;color:#1B3A6B}.sig3{width:78px;height:30px;left:4px;top:22px;opacity:.95;z-index:1}.seal3{width:50px;height:50px;right:-6px;top:10px;opacity:.84;z-index:2}
.qrw{display:flex;align-items:center;gap:14px;margin:4px 12px 10px;padding:10px;background:#fff;border:1px solid #D9DEE7;border-radius:12px}.qrw img{width:132px;height:132px;image-rendering:pixelated}.qrw div{display:flex;flex-direction:column;gap:3px}.qrw b{font-size:13px;color:#1B3A6B;letter-spacing:1px}.qrw span{font-size:11px;color:#5A6478}
.cno{display:flex;flex-direction:column;gap:1px;text-align:center}.cno b{font-size:10.5px;letter-spacing:.2px;color:#1B3A6B;white-space:nowrap}
.f{display:flex;flex-direction:column;gap:7px;min-width:0;flex:1}.f>div{display:flex;flex-direction:column;gap:1px}
.row{flex-direction:row!important;gap:10px}.row>div{display:flex;flex-direction:column;gap:1px;flex:1;min-width:0}
label{font-size:8.5px;font-weight:700;color:#5A6478;letter-spacing:1.2px}b{font-size:13.5px;font-weight:700;line-height:1.2}b.nm{font-size:19px;font-weight:800}span{font-size:12.5px;font-weight:600;line-height:1.3}
.sgw{position:relative;height:84px;margin:0 12px 2px}.sgname{position:absolute;right:16px;bottom:2px;width:170px;text-align:center;font-size:13px;font-weight:800;color:#1B3A6B;letter-spacing:.5px}.sig2{width:120px;height:46px;right:52px;top:6px;opacity:.95;z-index:1}.seal2{width:72px;height:72px;right:-4px;top:-6px;opacity:.84;z-index:2}
.ft{background:#F2F4F7;color:#3E4B5E;font-size:10px;font-weight:600;line-height:1.35;padding:7px 12px;border-top:1px solid #E3E8F0;text-align:center}
.fs{background:#1B3A6B;color:#fff;font-size:10.5px;font-weight:700;padding:7px 12px;letter-spacing:.3px;text-align:center}
.warn{background:var(--c);color:#fff;border-radius:12px;padding:14px 16px;font-size:13px;line-height:1.45}.warn b{display:block;font-size:11px;letter-spacing:1px;margin-bottom:4px;color:#fff}
.btns{margin-top:auto;display:flex;gap:8px}.btn{flex:1;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;gap:6px;font-size:13px;font-weight:700;text-decoration:none;border:2px solid var(--c);color:var(--c);background:#fff}.btn.p{background:var(--c);color:#fff}
.meta{font-size:10px;color:#3E4F5A;text-align:center;line-height:1.4}
.note{background:#fff;border:1px solid #D9DEE7;border-radius:12px;padding:12px 14px;font-size:12.5px;line-height:1.45;color:#2B3342}.note b{font-size:12.5px}
</style></head><body>
<div class="band"></div>
<div class="wm" aria-hidden="true">${Array(8).fill(`<div>${word} · ${word} · ${word}</div>`).join("")}</div>
<div class="wrap">
  <div class="st">${valid
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12.5l2.5 2.5L16 9.5"/></svg>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`}
    <div><div class="w" id="w">${word}</div><div class="s" id="s">${esc(reasonText)}</div></div></div>
  ${card}
  ${valid ? `<div class="note">Match the photo with the person in front of you. Tap <b>Refresh</b> to re-check the status; it also refreshes itself every 30 seconds.</div>` : `<div class="warn"><b>${pending ? "NOT YET ACTIVE" : "DO NOT ACCEPT THIS CARD"}</b>${esc(reasonText)}.</div>`}
  <div class="btns">
    <a class="btn" href="javascript:refresh()">↻ Refresh</a>
    <a class="btn p" href="javascript:location.reload()">⌁ Scan again</a>
  </div>
  <div class="meta">Verified at <span id="clk"></span> · Scan #${esc(d.scanId)}<br>This check has been logged for the landlord.</div>
</div>
<script>
var TOKEN=${JSON.stringify(token)};
function clk(){var d=new Date();document.getElementById('clk').textContent=d.toLocaleTimeString('en-IN',{hour12:false});}clk();setInterval(clk,1000);
var geo='';try{navigator.geolocation&&navigator.geolocation.getCurrentPosition(function(p){geo='?lat='+p.coords.latitude.toFixed(5)+'&lng='+p.coords.longitude.toFixed(5);},function(){},{timeout:4000});}catch(e){}
function refresh(){fetch('/api/v/'+TOKEN+geo,{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){if(j.result!==${JSON.stringify(d.result)})location.reload();}).catch(function(){});}
setInterval(refresh,30000);
document.addEventListener('contextmenu',function(e){e.preventDefault()});
</script></body></html>`;
}

function hashSeed(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h; }


/* ============================ QR (SVG) — qrcode-generator by Kazuhiko Arase (MIT), embedded ============================ */
function qrSvg(text) {
  const q = qrcode(0, "M"); q.addData(text, "Byte"); q.make();
  const n = q.getModuleCount(); const sz = n + 8; let rects = "";
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (q.isDark(y, x)) rects += `<rect x="${x + 4}" y="${y + 4}" width="1" height="1"/>`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${sz} ${sz}" shape-rendering="crispEdges"><rect width="${sz}" height="${sz}" fill="#fff"/><g fill="#000">${rects}</g></svg>`;
  return cors(new Response(svg, { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" } }));
}
function qrMatrix(text) { const q = qrcode(0, "M"); q.addData(text, "Byte"); q.make(); const n = q.getModuleCount(); const M = []; for (let y = 0; y < n; y++) { const r = []; for (let x = 0; x < n; x++) r.push(q.isDark(y, x) ? 1 : 0); M.push(r); } return M; }

const qrcode = (function(){
//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------

var qrcode = function() {

  //---------------------------------------------------------------------
  // qrcode
  //---------------------------------------------------------------------

  /**
   * qrcode
   * @param typeNumber 1 to 40
   * @param errorCorrectionLevel 'L','M','Q','H'
   */
  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    _this.addData = function(data, mode) {

      mode = mode || 'Byte';

      var newData = null;

      switch(mode) {
      case 'Numeric' :
        newData = qrNumber(data);
        break;
      case 'Alphanumeric' :
        newData = qrAlphaNum(data);
        break;
      case 'Byte' :
        newData = qr8BitByte(data);
        break;
      case 'Kanji' :
        newData = qrKanji(data);
        break;
      default :
        throw 'mode:' + mode;
      }

      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    _this.createTableTag = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var qrHtml = '';

      qrHtml += '<table style="';
      qrHtml += ' border-width: 0px; border-style: none;';
      qrHtml += ' border-collapse: collapse;';
      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';
      qrHtml += '">';
      qrHtml += '<tbody>';

      for (var r = 0; r < _this.getModuleCount(); r += 1) {

        qrHtml += '<tr>';

        for (var c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += ' border-width: 0px; border-style: none;';
          qrHtml += ' border-collapse: collapse;';
          qrHtml += ' padding: 0px; margin: 0px;';
          qrHtml += ' width: ' + cellSize + 'px;';
          qrHtml += ' height: ' + cellSize + 'px;';
          qrHtml += ' background-color: ';
          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';
          qrHtml += ';';
          qrHtml += '"/>';
        }

        qrHtml += '</tr>';
      }

      qrHtml += '</tbody>';
      qrHtml += '</table>';

      return qrHtml;
    };

    _this.createSvgTag = function(cellSize, margin, alt, title) {

      var opts = {};
      if (typeof arguments[0] == 'object') {
        // Called by options.
        opts = arguments[0];
        // overwrite cellSize and margin.
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      // Compose alt property surrogate
      alt = (typeof alt === 'string') ? {text: alt} : alt || {};
      alt.text = alt.text || null;
      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;

      // Compose title property surrogate
      title = (typeof title === 'string') ? {text: title} : title || {};
      title.text = title.text || null;
      title.id = (title.text) ? title.id || 'qrcode-title' : null;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var c, mc, r, mr, qrSvg='', rect;

      rect = 'l' + cellSize + ',0 0,' + cellSize +
        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';

      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : '';
      qrSvg += ' viewBox="0 0 ' + size + ' ' + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += (title.text || alt.text) ? ' role="img" aria-labelledby="' +
          escapeXml([title.id, alt.id].join(' ').trim() ) + '"' : '';
      qrSvg += '>';
      qrSvg += (title.text) ? '<title id="' + escapeXml(title.id) + '">' +
          escapeXml(title.text) + '</title>' : '';
      qrSvg += (alt.text) ? '<description id="' + escapeXml(alt.id) + '">' +
          escapeXml(alt.text) + '</description>' : '';
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';

      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c) ) {
            mc = c*cellSize+margin;
            qrSvg += 'M' + mc + ',' + mr + rect;
          }
        }
      }

      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += '</svg>';

      return qrSvg;
    };

    _this.createDataURL = function(cellSize, margin) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          var c = Math.floor( (x - min) / cellSize);
          var r = Math.floor( (y - min) / cellSize);
          return _this.isDark(r, c)? 0 : 1;
        } else {
          return 1;
        }
      } );
    };

    _this.createImgTag = function(cellSize, margin, alt) {

      cellSize = cellSize || 2;
      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;

      var img = '';
      img += '<img';
      img += '\u0020src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += '\u0020width="';
      img += size;
      img += '"';
      img += '\u0020height="';
      img += size;
      img += '"';
      if (alt) {
        img += '\u0020alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += '/>';

      return img;
    };

    var escapeXml = function(s) {
      var escaped = '';
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charAt(i);
        switch(c) {
        case '<': escaped += '&lt;'; break;
        case '>': escaped += '&gt;'; break;
        case '&': escaped += '&amp;'; break;
        case '"': escaped += '&quot;'; break;
        default : escaped += c; break;
        }
      }
      return escaped;
    };

    var _createHalfASCII = function(margin) {
      var cellSize = 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r1, r2, p;

      var blocks = {
        '██': '█',
        '█ ': '▀',
        ' █': '▄',
        '  ': ' '
      };

      var blocksLastLineNoMargin = {
        '██': '▀',
        '█ ': '▀',
        ' █': ' ',
        '  ': ' '
      };

      var ascii = '';
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = '█';

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = ' ';
          }

          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += ' ';
          }
          else {
            p += '█';
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];
        }

        ascii += '\n';
      }

      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;

      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }

      cellSize -= 1;
      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;

      var size = _this.getModuleCount() * cellSize + margin * 2;
      var min = margin;
      var max = size - margin;

      var y, x, r, p;

      var white = Array(cellSize+1).join('██');
      var black = Array(cellSize+1).join('  ');

      var ascii = '';
      var line = '';
      for (y = 0; y < size; y += 1) {
        r = Math.floor( (y - min) / cellSize);
        line = '';
        for (x = 0; x < size; x += 1) {
          p = 1;

          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }

          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.
          line += p ? white : black;
        }

        for (r = 0; r < cellSize; r += 1) {
          ascii += line + '\n';
        }
      }

      return ascii.substring(0, ascii.length-1);
    };

    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      var length = _this.getModuleCount();
      for (var row = 0; row < length; row++) {
        for (var col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';
          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);
        }
      }
    }

    return _this;
  };

  //---------------------------------------------------------------------
  // qrcode.stringToBytes
  //---------------------------------------------------------------------

  qrcode.stringToBytesFuncs = {
    'default' : function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        bytes.push(c & 0xff);
      }
      return bytes;
    }
  };

  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];

  //---------------------------------------------------------------------
  // qrcode.createStringToBytes
  //---------------------------------------------------------------------

  /**
   * @param unicodeData base64 string of byte array.
   * [16bit Unicode],[16bit Bytes], ...
   * @param numChars
   */
  qrcode.createStringToBytes = function(unicodeData, numChars) {

    // create conversion map.

    var unicodeMap = function() {

      var bin = base64DecodeInputStream(unicodeData);
      var read = function() {
        var b = bin.read();
        if (b == -1) throw 'eof';
        return b;
      };

      var count = 0;
      var unicodeMap = {};
      while (true) {
        var b0 = bin.read();
        if (b0 == -1) break;
        var b1 = read();
        var b2 = read();
        var b3 = read();
        var k = String.fromCharCode( (b0 << 8) | b1);
        var v = (b2 << 8) | b3;
        unicodeMap[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + ' != ' + numChars;
      }

      return unicodeMap;
    }();

    var unknownChar = '?'.charCodeAt(0);

    return function(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i += 1) {
        var c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          var b = unicodeMap[s.charAt(i)];
          if (typeof b == 'number') {
            if ( (b & 0xff) == b) {
              // 1byte
              bytes.push(b);
            } else {
              // 2bytes
              bytes.push(b >>> 8);
              bytes.push(b & 0xff);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };

  //---------------------------------------------------------------------
  // QRMode
  //---------------------------------------------------------------------

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  //---------------------------------------------------------------------
  // QRErrorCorrectionLevel
  //---------------------------------------------------------------------

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  //---------------------------------------------------------------------
  // QRMaskPattern
  //---------------------------------------------------------------------

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  //---------------------------------------------------------------------
  // QRUtil
  //---------------------------------------------------------------------

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        // 1 - 9

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        // 10 - 26

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        // 27 - 40

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // QRMath
  //---------------------------------------------------------------------

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrPolynomial
  //---------------------------------------------------------------------

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // QRRSBlock
  //---------------------------------------------------------------------

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  //---------------------------------------------------------------------
  // qrBitBuffer
  //---------------------------------------------------------------------

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrNumber
  //---------------------------------------------------------------------

  var qrNumber = function(data) {

    var _mode = QRMode.MODE_NUMBER;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var data = _data;

      var i = 0;

      while (i + 2 < data.length) {
        buffer.put(strToNum(data.substring(i, i + 3) ), 10);
        i += 3;
      }

      if (i < data.length) {
        if (data.length - i == 1) {
          buffer.put(strToNum(data.substring(i, i + 1) ), 4);
        } else if (data.length - i == 2) {
          buffer.put(strToNum(data.substring(i, i + 2) ), 7);
        }
      }
    };

    var strToNum = function(s) {
      var num = 0;
      for (var i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i) );
      }
      return num;
    };

    var chatToNum = function(c) {
      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      }
      throw 'illegal char :' + c;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrAlphaNum
  //---------------------------------------------------------------------

  var qrAlphaNum = function(data) {

    var _mode = QRMode.MODE_ALPHA_NUM;
    var _data = data;

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _data.length;
    };

    _this.write = function(buffer) {

      var s = _data;

      var i = 0;

      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i) ) * 45 +
          getCode(s.charAt(i + 1) ), 11);
        i += 2;
      }

      if (i < s.length) {
        buffer.put(getCode(s.charAt(i) ), 6);
      }
    };

    var getCode = function(c) {

      if ('0' <= c && c <= '9') {
        return c.charCodeAt(0) - '0'.charCodeAt(0);
      } else if ('A' <= c && c <= 'Z') {
        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
      } else {
        switch (c) {
        case ' ' : return 36;
        case '$' : return 37;
        case '%' : return 38;
        case '*' : return 39;
        case '+' : return 40;
        case '-' : return 41;
        case '.' : return 42;
        case '/' : return 43;
        case ':' : return 44;
        default :
          throw 'illegal char :' + c;
        }
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qr8BitByte
  //---------------------------------------------------------------------

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _data = data;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // qrKanji
  //---------------------------------------------------------------------

  var qrKanji = function(data) {

    var _mode = QRMode.MODE_KANJI;
    var _data = data;

    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];
    if (!stringToBytes) {
      throw 'sjis not supported.';
    }
    !function(c, code) {
      // self test for sjis support.
      var test = stringToBytes(c);
      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {
        throw 'sjis not supported.';
      }
    }('\u53cb', 0x9746);

    var _bytes = stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };

    _this.write = function(buffer) {

      var data = _bytes;

      var i = 0;

      while (i + 1 < data.length) {

        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);

        if (0x8140 <= c && c <= 0x9FFC) {
          c -= 0x8140;
        } else if (0xE040 <= c && c <= 0xEBBF) {
          c -= 0xC140;
        } else {
          throw 'illegal char at ' + (i + 1) + '/' + c;
        }

        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);

        buffer.put(c, 13);

        i += 2;
      }

      if (i < data.length) {
        throw 'illegal char at ' + (i + 1);
      }
    };

    return _this;
  };

  //=====================================================================
  // GIF Support etc.
  //

  //---------------------------------------------------------------------
  // byteArrayOutputStream
  //---------------------------------------------------------------------

  var byteArrayOutputStream = function() {

    var _bytes = [];

    var _this = {};

    _this.writeByte = function(b) {
      _bytes.push(b & 0xff);
    };

    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };

    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (var i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };

    _this.writeString = function(s) {
      for (var i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i) );
      }
    };

    _this.toByteArray = function() {
      return _bytes;
    };

    _this.toString = function() {
      var s = '';
      s += '[';
      for (var i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ',';
        }
        s += _bytes[i];
      }
      s += ']';
      return s;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64EncodeOutputStream
  //---------------------------------------------------------------------

  var base64EncodeOutputStream = function() {

    var _buffer = 0;
    var _buflen = 0;
    var _length = 0;
    var _base64 = '';

    var _this = {};

    var writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 0x3f) );
    };

    var encode = function(n) {
      if (n < 0) {
        // error.
      } else if (n < 26) {
        return 0x41 + n;
      } else if (n < 52) {
        return 0x61 + (n - 26);
      } else if (n < 62) {
        return 0x30 + (n - 52);
      } else if (n == 62) {
        return 0x2b;
      } else if (n == 63) {
        return 0x2f;
      }
      throw 'n:' + n;
    };

    _this.writeByte = function(n) {

      _buffer = (_buffer << 8) | (n & 0xff);
      _buflen += 8;
      _length += 1;

      while (_buflen >= 6) {
        writeEncoded(_buffer >>> (_buflen - 6) );
        _buflen -= 6;
      }
    };

    _this.flush = function() {

      if (_buflen > 0) {
        writeEncoded(_buffer << (6 - _buflen) );
        _buffer = 0;
        _buflen = 0;
      }

      if (_length % 3 != 0) {
        // padding
        var padlen = 3 - _length % 3;
        for (var i = 0; i < padlen; i += 1) {
          _base64 += '=';
        }
      }
    };

    _this.toString = function() {
      return _base64;
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // base64DecodeInputStream
  //---------------------------------------------------------------------

  var base64DecodeInputStream = function(str) {

    var _str = str;
    var _pos = 0;
    var _buffer = 0;
    var _buflen = 0;

    var _this = {};

    _this.read = function() {

      while (_buflen < 8) {

        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw 'unexpected end of file./' + _buflen;
        }

        var c = _str.charAt(_pos);
        _pos += 1;

        if (c == '=') {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/) ) {
          // ignore if whitespace.
          continue;
        }

        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );
        _buflen += 6;
      }

      var n = (_buffer >>> (_buflen - 8) ) & 0xff;
      _buflen -= 8;
      return n;
    };

    var decode = function(c) {
      if (0x41 <= c && c <= 0x5a) {
        return c - 0x41;
      } else if (0x61 <= c && c <= 0x7a) {
        return c - 0x61 + 26;
      } else if (0x30 <= c && c <= 0x39) {
        return c - 0x30 + 52;
      } else if (c == 0x2b) {
        return 62;
      } else if (c == 0x2f) {
        return 63;
      } else {
        throw 'c:' + c;
      }
    };

    return _this;
  };

  //---------------------------------------------------------------------
  // gifImage (B/W)
  //---------------------------------------------------------------------

  var gifImage = function(width, height) {

    var _width = width;
    var _height = height;
    var _data = new Array(width * height);

    var _this = {};

    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };

    _this.write = function(out) {

      //---------------------------------
      // GIF Signature

      out.writeString('GIF87a');

      //---------------------------------
      // Screen Descriptor

      out.writeShort(_width);
      out.writeShort(_height);

      out.writeByte(0x80); // 2bit
      out.writeByte(0);
      out.writeByte(0);

      //---------------------------------
      // Global Color Map

      // black
      out.writeByte(0x00);
      out.writeByte(0x00);
      out.writeByte(0x00);

      // white
      out.writeByte(0xff);
      out.writeByte(0xff);
      out.writeByte(0xff);

      //---------------------------------
      // Image Descriptor

      out.writeString(',');
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);

      //---------------------------------
      // Local Color Map

      //---------------------------------
      // Raster Data

      var lzwMinCodeSize = 2;
      var raster = getLZWRaster(lzwMinCodeSize);

      out.writeByte(lzwMinCodeSize);

      var offset = 0;

      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }

      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0x00);

      //---------------------------------
      // GIF Terminator
      out.writeString(';');
    };

    var bitOutputStream = function(out) {

      var _out = out;
      var _bitLength = 0;
      var _bitBuffer = 0;

      var _this = {};

      _this.write = function(data, length) {

        if ( (data >>> length) != 0) {
          throw 'length over';
        }

        while (_bitLength + length >= 8) {
          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );
          length -= (8 - _bitLength);
          data >>>= (8 - _bitLength);
          _bitBuffer = 0;
          _bitLength = 0;
        }

        _bitBuffer = (data << _bitLength) | _bitBuffer;
        _bitLength = _bitLength + length;
      };

      _this.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };

      return _this;
    };

    var getLZWRaster = function(lzwMinCodeSize) {

      var clearCode = 1 << lzwMinCodeSize;
      var endCode = (1 << lzwMinCodeSize) + 1;
      var bitLength = lzwMinCodeSize + 1;

      // Setup LZWTable
      var table = lzwTable();

      for (var i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i) );
      }
      table.add(String.fromCharCode(clearCode) );
      table.add(String.fromCharCode(endCode) );

      var byteOut = byteArrayOutputStream();
      var bitOut = bitOutputStream(byteOut);

      // clear code
      bitOut.write(clearCode, bitLength);

      var dataIndex = 0;

      var s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;

      while (dataIndex < _data.length) {

        var c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;

        if (table.contains(s + c) ) {

          s = s + c;

        } else {

          bitOut.write(table.indexOf(s), bitLength);

          if (table.size() < 0xfff) {

            if (table.size() == (1 << bitLength) ) {
              bitLength += 1;
            }

            table.add(s + c);
          }

          s = c;
        }
      }

      bitOut.write(table.indexOf(s), bitLength);

      // end code
      bitOut.write(endCode, bitLength);

      bitOut.flush();

      return byteOut.toByteArray();
    };

    var lzwTable = function() {

      var _map = {};
      var _size = 0;

      var _this = {};

      _this.add = function(key) {
        if (_this.contains(key) ) {
          throw 'dup key:' + key;
        }
        _map[key] = _size;
        _size += 1;
      };

      _this.size = function() {
        return _size;
      };

      _this.indexOf = function(key) {
        return _map[key];
      };

      _this.contains = function(key) {
        return typeof _map[key] != 'undefined';
      };

      return _this;
    };

    return _this;
  };

  var createDataURL = function(width, height, getPixel) {
    var gif = gifImage(width, height);
    for (var y = 0; y < height; y += 1) {
      for (var x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y) );
      }
    }

    var b = byteArrayOutputStream();
    gif.write(b);

    var base64 = base64EncodeOutputStream();
    var bytes = b.toByteArray();
    for (var i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();

    return 'data:image/gif;base64,' + base64;
  };

  //---------------------------------------------------------------------
  // returns qrcode function.

  return qrcode;
}();

// multibyte support
!function() {

  qrcode.stringToBytesFuncs['UTF-8'] = function(s) {
    // http://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array
    function toUTF8Array(str) {
      var utf8 = [];
      for (var i=0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
          utf8.push(0xc0 | (charcode >> 6),
              0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
          utf8.push(0xe0 | (charcode >> 12),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
          i++;
          // UTF-16 encodes 0x10000-0x10FFFF by
          // subtracting 0x10000 and splitting the
          // 20 bits of 0x0-0xFFFFF into two halves
          charcode = 0x10000 + (((charcode & 0x3ff)<<10)
            | (str.charCodeAt(i) & 0x3ff));
          utf8.push(0xf0 | (charcode >>18),
              0x80 | ((charcode>>12) & 0x3f),
              0x80 | ((charcode>>6) & 0x3f),
              0x80 | (charcode & 0x3f));
        }
      }
      return utf8;
    }
    return toUTF8Array(s);
  };

}();

(function (factory) {
  if (typeof define === 'function' && define.amd) {
      define([], factory);
  } else if (typeof exports === 'object') {
      module.exports = factory();
  }
}(function () {
    return qrcode;
}));

return qrcode;
})();
