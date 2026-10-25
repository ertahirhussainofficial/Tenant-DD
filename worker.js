/**
 * Tenant Identity Card — Cloudflare Worker backend
 * Firebase RTDB (via REST + database secret) + Telegram (file storage) + HMAC QR tokens + HS256 JWT.
 *
 * Roles:  admin (you, ADMIN_KEY) → landlord (phone+PIN) → viewer (loginId+PIN, created by landlord)
 */

export default {
  async fetch(request, env, ctx) {
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
  if ((x = match(p, "/vault/:tid/:idx")) && m === "GET") return vaultFile(env, x.tid, x.idx, url);
  if ((x = match(p, "/c/:cardNo")) && m === "GET") return cardLookup(env, x.cardNo);

  // ---------- Auth ----------
  if (p === "/auth/landlord" && m === "POST") return authLandlord(request, env);
  if (p === "/auth/viewer" && m === "POST") return authViewer(request, env);

  // ---------- Super admin (you) ----------
  if (p.startsWith("/admin/")) {
    if (request.headers.get("X-Admin-Key") !== env.ADMIN_KEY) throw err(401, "bad admin key");
    if (p === "/admin/landlord" && m === "POST") return adminCreateLandlord(request, env);
    if (p === "/admin/landlords" && m === "GET") return json({ ok: true, landlords: await fbGet(env, "landlords") });
    if ((x = match(p, "/admin/landlord/:lid")) && m === "PATCH") return adminPatchLandlord(request, env, x.lid);
  }

  // ---------- Landlord ----------
  if (p.startsWith("/landlord/")) {
    const u = await auth(request, env, "landlord");
    if (p === "/landlord/me" && m === "GET") return json({ ok: true, me: await fbGet(env, "landlords/" + u.lid) });
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
        property: P || {}, landlord: { name: L.name, phone: L.phone, hasSignature: !!L.signature, hasSeal: !!L.seal },
        photoUrl: T.photo ? env.BASE_URL + "/photo/" + token : null,
        sigUrl: L.signature ? env.BASE_URL + "/sig/" + token : null,
        sealUrl: L.seal ? env.BASE_URL + "/seal/" + token : null });
    }
    if ((x = match(p, "/landlord/tenant/:tid")) && m === "PATCH") return patchTenant(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/photo")) && m === "POST") return uploadPhoto(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/vault")) && m === "POST") return uploadVault(request, env, u, x.tid);
    if ((x = match(p, "/landlord/tenant/:tid/vault/:idx")) && m === "DELETE") return deleteVault(env, u, x.tid, x.idx);
    if ((x = match(p, "/landlord/tenant/:tid/vault")) && m === "GET") return listVault(env, u, x.tid);
    if (p === "/landlord/tenants" && m === "GET") return json({ ok: true, tenants: withStatus(await fbQuery(env, "tenants", "lid", u.lid)) });
    if ((x = match(p, "/landlord/logs/:tid")) && m === "GET") return tenantLogs(env, u, x.tid);
    if (p === "/landlord/viewer" && m === "POST") return createViewer(request, env, u);
    if ((x = match(p, "/landlord/viewer/:vid")) && m === "PATCH") return patchViewer(request, env, u, x.vid);
    if (p === "/landlord/viewers" && m === "GET") return json({ ok: true, viewers: strip(await fbQuery(env, "viewers", "lid", u.lid)) });
    if (p === "/landlord/signature" && m === "POST") return uploadLandlordImage(request, env, u, "signature");
    if (p === "/landlord/seal" && m === "POST") return uploadLandlordImage(request, env, u, "seal");
    if ((x = match(p, "/landlord/image/:kind")) && m === "GET") return landlordImage(env, u, x.kind);
  }

  // ---------- Viewer (police / administration) ----------
  if (p.startsWith("/viewer/")) {
    const u = await auth(request, env, "viewer");
    if (p === "/viewer/me" && m === "GET") return json({ ok: true, me: strip1(await fbGet(env, "viewers/" + u.vid)) });
    if (p === "/viewer/scan" && m === "POST") return viewerScan(request, env, u);
    if (p === "/viewer/note" && m === "POST") return viewerNote(request, env, u);
    if (p === "/viewer/myscans" && m === "GET") return json({ ok: true, scans: await fbGet(env, "viewerScans/" + u.vid) });
  }

  throw err(404, "not found");
}

/* ============================ AUTH ============================ */

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
  const T = {
    lid: u.lid, pid: b.pid, roomNo: String(b.roomNo),
    name: b.name, parentage: b.parentage, dob: b.dob, permAddr: b.permAddr,
    phone: b.phone || "", emergency: b.emergency || "",
    idDocType: b.idDocType || "", idDocLast4: (b.idDocLast4 || "").slice(-4),
    cardNo, tokenVer: 1, status: b.activate === false ? "pending" : "active",
    issuedAt: now, validTill: now + days * 86400000,
    photo: null, vault: [], createdAt: now
  };
  await fbPut(env, "tenants/" + tid, T);
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
      patch.status = "active"; patch.validTill = now + Number(b.validDays || env.DEFAULT_VALID_DAYS) * 86400000;
      patch.revokedAt = null; patch.revokeReason = null; break;
    case "activate": patch.status = "active"; break;
    case "update":
      for (const k of ["roomNo", "name", "parentage", "dob", "permAddr", "phone", "emergency", "idDocType", "idDocLast4", "validTill"])
        if (b[k] !== undefined) patch[k] = k === "idDocLast4" ? String(b[k]).slice(-4) : b[k];
      break;
    default: throw err(400, "unknown action");
  }
  await fbPatch(env, "tenants/" + tid, patch);
  const ver = patch.tokenVer || T.tokenVer || 1;
  const token = await cardToken(env, tid, ver);
  return json({ ok: true, token, qrUrl: env.BASE_URL + "/v/" + token });
}

async function uploadPhoto(request, env, u, tid) {
  await ownTenant(env, u, tid);
  const f = await getFile(request);
  const tg = await tgUpload(env, f, `photo ${tid}`);
  await fbPatch(env, "tenants/" + tid, { photo: tg });
  return json({ ok: true, photo: tg });
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
  if (!r.ok) return json({ ok: true, result: r.result, reason: r.reason, scanId });

  const { tid, T, P, L } = r;
  const out = {
    ok: true, result: "valid", scanId, tid, cardNo: T.cardNo,
    tenant: pick(T, ["name", "parentage", "dob", "permAddr", "phone", "emergency", "roomNo", "idDocType", "idDocLast4", "issuedAt", "validTill", "status"]),
    property: { address: P.address, policeStation: P.policeStation },
    landlord: { name: L.name, phone: L.phone },
    photoUrl: T.photo ? env.BASE_URL + "/photo/" + token : null,
    sigUrl: L.signature ? env.BASE_URL + "/sig/" + token : null,
    sealUrl: L.seal ? env.BASE_URL + "/seal/" + token : null,
    perms: u.perms
  };
  if (u.perms?.vault) out.vault = await signedVault(env, tid, T.vault || []);
  if (u.perms?.history) {
    const [scans, notes] = await Promise.all([fbGet(env, "scans/" + tid), fbGet(env, "notes/" + tid)]);
    out.scans = scans || {}; out.notes = notes || {};
  }
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
  await fbPut(env, "notes/" + tid + "/" + nid, { vid: u.vid, viewerName: u.name, dept: u.dept, tag, text: String(text || "").slice(0, 500), at: Date.now() });
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
    policeStation: P.policeStation, landlord: L.name,
    issuedAt: T.issuedAt, validTill: T.validTill, revokedAt: T.revokedAt || null,
    photoUrl: T.photo ? env.BASE_URL + "/photo/" + token : null,
    sigUrl: L.signature ? env.BASE_URL + "/sig/" + token : null,
    sealUrl: L.seal ? env.BASE_URL + "/seal/" + token : null
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
    by: extra.by, byName: extra.byName || null, dept: extra.dept || null,
    ip: request.headers.get("CF-Connecting-IP") || null,
    city: cf.city || null, region: cf.region || null, country: cf.country || null,
    lat: extra.lat ? Number(extra.lat) : (cf.latitude ? Number(cf.latitude) : null),
    lng: extra.lng ? Number(extra.lng) : (cf.longitude ? Number(cf.longitude) : null),
    ua: (request.headers.get("User-Agent") || "").slice(0, 120)
  };
  if (r.tid) {
    await fbPut(env, "scans/" + r.tid + "/" + id("S"), rec);
    if (extra.by && extra.by !== "public") await fbPut(env, "viewerScans/" + extra.by + "/" + id("S"), { ...rec, tid: r.tid, cardNo: r.T?.cardNo });
  } else {
    await fbPut(env, "badScans/" + id("S"), rec);
  }
  return scanId;
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
  return { file_id: d.file_id, name: d.file_name || file.name || "file", mime: d.mime_type || file.type || "application/octet-stream", size: d.file_size || file.size || 0, msg: j.result.message_id };
}

async function tgServe(env, fileId, mime, name) {
  const r = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
  const j = await r.json();
  if (!j.ok) throw err(502, "telegram getFile failed");
  const f = await fetch(`https://api.telegram.org/file/bot${env.TG_BOT_TOKEN}/${j.result.file_path}`);
  if (!f.ok) throw err(502, "telegram download failed");
  const h = new Headers({ "Content-Type": mime || "application/octet-stream", "Cache-Control": "private, max-age=60", "X-Content-Type-Options": "nosniff" });
  if (name) h.set("Content-Disposition", `inline; filename="${name.replace(/"/g, "")}"`);
  return cors(new Response(f.body, { status: 200, headers: h }));
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
async function fbGet(env, path, q) { const r = await fetch(fbUrl(env, path, q)); return r.json(); }
async function fbPut(env, path, body) { const r = await fetch(fbUrl(env, path), { method: "PUT", body: JSON.stringify(body) }); if (!r.ok) throw err(500, "db write failed"); }
async function fbPatch(env, path, body) { const r = await fetch(fbUrl(env, path), { method: "PATCH", body: JSON.stringify(body) }); if (!r.ok) throw err(500, "db write failed"); }
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
    FAKE_OR_DAMAGED: "QR code is not genuine or is damaged",
    UNKNOWN_CARD: "Card not found"
  }[d.reason] || (valid ? "Active tenant · verified live just now" : "");

  const card = d.cardNo ? `
<div class="card ${valid ? "" : "dim"}">
  <div class="hd"><div><div class="t1">TENANT IDENTITY CARD</div><div class="t2">Issued by ${esc(d.landlord)} (Landlord)</div></div>
    <div class="room"><div class="rl">ROOM</div><div class="rn">${esc(d.roomNo)}</div></div></div>
  <div class="bd">
    <div class="phw"><div class="ph">${d.photoUrl ? `<img src="${esc(d.photoUrl)}" alt="Tenant photo">` : `<span>NO PHOTO</span>`}</div>
      ${d.sealUrl ? `<img class="stp seal1" src="${esc(d.sealUrl)}" alt="">` : ""}${d.sigUrl ? `<img class="stp sig1" src="${esc(d.sigUrl)}" alt="">` : ""}</div>
    <div class="f">
      <div><label>NAME</label><b class="nm">${esc(d.name)}</b></div>
      <div><label>FATHER'S / HUSBAND'S NAME</label><b>${esc(d.parentage)}</b></div>
      <div><label>DATE OF BIRTH</label><b>${esc(d.dob)}</b></div>
    </div>
  </div>
  <div class="bd2">
    <div><label>${valid ? "RENTED ROOM ADDRESS" : "WAS REGISTERED AT"}</label><span>Room ${esc(d.roomNo)}, ${esc(d.roomAddr)}</span></div>
    <div><label>PERMANENT ADDRESS</label><span>${esc(d.permAddr)}</span></div>
    <div><label>POLICE STATION</label><b>${esc(d.policeStation || "—")}</b></div>
    <div class="row"><div><label>CARD NO.</label><b>${esc(d.cardNo)}</b></div><div><label>${valid ? "VALID TILL" : "PERIOD"}</label><b style="color:${col}">${valid ? fmtDate(d.validTill) : fmtDate(d.issuedAt) + " – " + fmtDate(d.revokedAt || d.validTill)}</b></div>
      <div class="sgw"><div class="sgb">${d.sigUrl ? `<img class="stp sig2" src="${esc(d.sigUrl)}" alt="Landlord signature">` : ""}</div><label>LANDLORD</label>${d.sealUrl ? `<img class="stp seal2" src="${esc(d.sealUrl)}" alt="Landlord seal">` : ""}</div></div>
  </div>
  <div class="ft"></div>
</div>` : `<div class="card dim"><div class="bd2"><b>No card data</b><span>${esc(reasonText)}</span></div></div>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>${word} · ${esc(env.APP_NAME)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--c:${col};--bg:${bg}}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:#141413;min-height:100vh;position:relative;overflow-x:hidden;-webkit-user-select:none;user-select:none}
.wm{position:fixed;inset:-40%;display:flex;flex-direction:column;gap:70px;transform:rotate(-32deg);color:var(--c);opacity:.14;font-size:84px;font-weight:900;letter-spacing:6px;white-space:nowrap;pointer-events:none;z-index:0}
.band{position:fixed;left:0;right:0;top:0;height:6px;background:var(--c);animation:pulse 3s infinite;z-index:3}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.wrap{position:relative;z-index:1;max-width:430px;margin:0 auto;padding:22px 16px 24px;display:flex;flex-direction:column;gap:12px;min-height:100vh}
.st{display:flex;align-items:center;gap:12px;color:var(--c)}.st svg{width:40px;height:40px;flex-shrink:0}.st .w{font-size:30px;font-weight:900;letter-spacing:2px;line-height:1}.st .s{font-size:12px;font-weight:600;opacity:.85}
.card{background:#fff;border-radius:16px;overflow:hidden;border:2px solid var(--c);box-shadow:0 8px 24px rgba(0,0,0,.12)}.card.dim{filter:grayscale(.6);opacity:.92}
.hd{background:#1B3A6B;color:#fff;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;gap:8px}.t1{font-size:12px;font-weight:800;letter-spacing:1px}.t2{font-size:9px;opacity:.85}
.room{background:#fff;color:#1B3A6B;border-radius:8px;padding:6px 10px;text-align:center;line-height:1}.rl{font-size:8px;font-weight:700;letter-spacing:1px}.rn{font-size:20px;font-weight:900}
.bd{display:flex;gap:12px;padding:12px 14px}.ph{width:92px;height:112px;border-radius:8px;background:#F2F4F7;border:1px solid #D9DEE7;flex-shrink:0;overflow:hidden;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:600;color:#5A6478}.ph img{width:100%;height:100%;object-fit:cover}
.phw{position:relative;width:92px;height:112px;flex-shrink:0}.stp{position:absolute;pointer-events:none;object-fit:contain}
.seal1{width:52px;height:52px;right:-12px;bottom:-12px;transform:rotate(-14deg);opacity:.78}.sig1{width:60px;height:26px;right:0;bottom:14px;transform:rotate(-8deg);opacity:.92}
.sgw{position:relative;display:flex;flex-direction:column;align-items:center;gap:1px}.sgb{width:110px;height:34px;border-bottom:1.5px solid #141413;display:flex;align-items:flex-end;justify-content:center}
.sig2{position:static;width:84px;height:30px;margin-left:16px;transform:rotate(-3deg)}.seal2{width:54px;height:54px;left:-10px;top:-18px;transform:rotate(12deg);opacity:.78}
.f{display:flex;flex-direction:column;gap:7px;min-width:0;flex:1}.f div,.bd2>div{display:flex;flex-direction:column;gap:1px}
label{font-size:9px;font-weight:600;color:#5A6478;letter-spacing:1px}b{font-size:13px;font-weight:600}b.nm{font-size:17px;font-weight:800}span{font-size:12px;font-weight:500;line-height:1.35}
.bd2{padding:0 14px 12px;display:flex;flex-direction:column;gap:8px}.row{flex-direction:row!important;justify-content:space-between;gap:10px}.row>div{display:flex;flex-direction:column;gap:1px}
.ft{height:6px;background:#1B3A6B}
.warn{background:var(--c);color:#fff;border-radius:12px;padding:14px 16px;font-size:13px;line-height:1.45}.warn b{display:block;font-size:11px;letter-spacing:1px;margin-bottom:4px;color:#fff}
.btns{margin-top:auto;display:flex;gap:8px}.btn{flex:1;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;gap:6px;font-size:13px;font-weight:700;text-decoration:none;border:2px solid var(--c);color:var(--c);background:#fff}.btn.p{background:var(--c);color:#fff}
.meta{font-size:10px;color:#3E4F5A;text-align:center;line-height:1.4}
</style></head><body>
<div class="band"></div>
<div class="wm" aria-hidden="true">${Array(8).fill(`<div>${word} · ${word} · ${word}</div>`).join("")}</div>
<div class="wrap">
  <div class="st">${valid
    ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12.5l2.5 2.5L16 9.5"/></svg>`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`}
    <div><div class="w" id="w">${word}</div><div class="s" id="s">${esc(reasonText)}</div></div></div>
  ${card}
  ${valid ? "" : `<div class="warn"><b>${pending ? "NOT YET ACTIVE" : "DO NOT ACCEPT THIS CARD"}</b>${esc(reasonText)}.</div>`}
  <div class="btns">
    <a class="btn" href="javascript:refresh()">↻ Refresh</a>
    <a class="btn p" href="javascript:location.reload()">⌁ Scan again</a>
  </div>
  <div class="meta">Verified at <span id="clk"></span> · Scan #${esc(d.scanId)} · auto-refreshes every 30 s<br>Match the photo with the person. This scan is logged.</div>
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
