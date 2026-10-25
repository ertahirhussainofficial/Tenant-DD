# Tenant ID Card — Backend setup

Files: `worker.js` (Cloudflare Worker), `wrangler.toml`, `firebase.rules.json`.

## 1. Firebase (5 min)
1. console.firebase.google.com → Add project `tenantcard` (Analytics off).
2. Build → Realtime Database → Create → region `asia-southeast1` → **Locked mode**.
3. Rules tab → paste `firebase.rules.json` → Publish.
4. Project settings (gear) → Service accounts → **Database secrets** → Show → copy. This is `FB_SECRET`.
5. Copy the DB URL shown at top of Data tab. This is `FB_DB_URL`.

## 2. Telegram storage (5 min)
1. @BotFather → `/newbot` → copy token → `TG_BOT_TOKEN`.
2. Create a **private channel** (e.g. "TenantCard Vault"). Add the bot as **Admin** (needs "Post messages").
3. Get the channel id: post any message in the channel, then open  
   `https://api.telegram.org/bot<TOKEN>/getUpdates` — look for `"chat":{"id":-100xxxxxxxxxx`. That is `TG_CHAT_ID`.  
   (If empty, forward a channel post to @userinfobot — it shows the id.)
4. Photos, signatures and vault documents are uploaded as Telegram *documents* (original quality, up to 50 MB). Only the `file_id` is kept in Firebase. Telegram never shows these publicly; the Worker fetches on demand.

## 3. Cloudflare Worker (5 min)
```bash
npm i -g wrangler
wrangler login
cd tenantcard-backend
wrangler deploy                      # first deploy → note the workers.dev URL
# put that URL into wrangler.toml BASE_URL, then set secrets:
wrangler secret put FB_DB_URL
wrangler secret put FB_SECRET
wrangler secret put HMAC_SECRET      # openssl rand -hex 32
wrangler secret put JWT_SECRET       # openssl rand -hex 32
wrangler secret put ADMIN_KEY        # openssl rand -hex 24
wrangler secret put TG_BOT_TOKEN
wrangler secret put TG_CHAT_ID
wrangler deploy                      # redeploy with BASE_URL
```
Optional: Workers → your worker → Settings → Triggers → add custom domain `verify.yourdomain.com`; then set BASE_URL to it.

Rate limit (recommended): Cloudflare dashboard → Security → WAF → Rate limiting rules → path starts with `/v/` or `/api/` → 30 req / 1 min / IP → Block 1 min.

## 4. Create the first landlord (you, as super-admin)
```bash
curl -X POST $BASE/admin/landlord -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Mohd. Ashraf","phone":"9876543210","pin":"4321"}'
```

## 5. Quick end-to-end test (curl)
```bash
BASE=https://tenant-verify.xxx.workers.dev

# landlord login
TOK=$(curl -s -X POST $BASE/auth/landlord -H "Content-Type: application/json" -d '{"phone":"9876543210","pin":"4321"}' | jq -r .token)

# property
PID=$(curl -s -X POST $BASE/landlord/property -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"label":"Lal Chowk house","address":"H.No. 12, Lal Chowk, Srinagar 190001","policeStation":"P.S. Kothibagh","rooms":["01","02","03"]}' | jq -r .pid)

# tenant → returns cardNo + qrUrl
curl -s -X POST $BASE/landlord/tenant -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d "{\"pid\":\"$PID\",\"roomNo\":\"03\",\"name\":\"RAHUL KUMAR\",\"parentage\":\"RAMESH KUMAR\",\"dob\":\"12/05/1996\",\"permAddr\":\"Vill. Mahuabagh, Dist. Patna, Bihar 801103\",\"phone\":\"8XXXXXXXXX\",\"idDocType\":\"Aadhaar\",\"idDocLast4\":\"4821\"}"

# photo + vault doc (multipart)
curl -s -X POST $BASE/landlord/tenant/<TID>/photo -H "Authorization: Bearer $TOK" -F file=@photo.jpg
curl -s -X POST $BASE/landlord/tenant/<TID>/vault -H "Authorization: Bearer $TOK" -F file=@aadhaar.pdf -F label="Aadhaar"

# open qrUrl in a browser → green VALID page
# revoke → page turns red
curl -s -X PATCH $BASE/landlord/tenant/<TID> -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" -d '{"action":"revoke","reason":"Tenant left"}'

# create a police login
curl -s -X POST $BASE/landlord/viewer -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"name":"SI Ravi Sharma","dept":"police","badgeNo":"JK1234","station":"P.S. Kothibagh","loginId":"ravi.ps","pin":"1122","perms":{"vault":true,"note":true,"history":true},"expiresAt":null}'
```

## 6. API summary (what the APK will call)

| Method | Path | Auth | Body / notes |
|---|---|---|---|
| POST | /auth/landlord | – | {phone,pin} → token |
| POST | /auth/viewer | – | {loginId,pin} → token, perms |
| GET | /landlord/me, /properties, /tenants, /viewers | landlord | |
| POST | /landlord/property | landlord | {label,address,policeStation,rooms:[...]} |
| PATCH | /landlord/property/:pid | landlord | same fields |
| POST | /landlord/tenant | landlord | {pid,roomNo,name,parentage,dob,permAddr,phone,emergency,idDocType,idDocLast4,validDays,activate} → cardNo, token, qrUrl |
| PATCH | /landlord/tenant/:tid | landlord | {action: revoke\|lost\|reissue\|renew\|activate\|update, ...} → new token/qrUrl |
| POST | /landlord/tenant/:tid/photo | landlord | multipart `file` |
| POST | /landlord/tenant/:tid/vault | landlord | multipart `file`, `label` |
| GET/DELETE | /landlord/tenant/:tid/vault[/:idx] | landlord | signed links (5 min) |
| POST | /landlord/signature | landlord | multipart `file` (landlord signature PNG) |
| GET | /landlord/logs/:tid | landlord | scans + notes |
| POST | /landlord/viewer | landlord | {name,dept,badgeNo,station,loginId,pin,perms:{vault,note,history},expiresAt} |
| PATCH | /landlord/viewer/:vid | landlord | perms / status:"disabled" / pin / expiresAt |
| POST | /viewer/scan | viewer | {token,lat,lng} → full details (+vault if perm) |
| POST | /viewer/note | viewer | {tid, tag: DOC_NOT_CLEAR\|SUSPECTED_FAKE\|ADDRESS_MISMATCH\|PERSON_MISMATCH\|OTHER, text} |
| GET | /viewer/myscans | viewer | |
| GET | /v/:token | public | HTML scan page (green/red) |
| GET | /api/v/:token | public | JSON (page auto-refresh) |
| GET | /c/:cardNo | public | lookup by printed number → redirects to /v/ |
| POST | /admin/landlord | X-Admin-Key | {name,phone,pin} |

QR content = `BASE_URL/v/<token>`. Token = base64url(tid.version) + "." + HMAC. Reissue/lost bumps version → old QR shows NOT VALID.


## 7. v2 update (app v2.0) — what changed on the backend
- Re-paste `firebase.rules.json` into Firebase → Rules (new indexes for `feed`, `adminFeed`, `viewerScans`, `badScans`).
- `wrangler.toml` has new vars: `APP_VERSION` (bump when you ship a new APK), `APK_URL` (download link shown in-app), `APP_NOTES`.
- New endpoints used by the app: `/auth/login` (one login for all roles), `/landlord/dashboard`, `/landlord/rooms`, `/landlord/feed`, `/landlord/me` (PATCH: name, helpline, tgChatId, alerts), `/landlord/pin`, `/landlord/tg-test`, `/landlord/export.csv`, `DELETE /landlord/property/:pid`, `DELETE /landlord/viewer/:vid`, `/admin/overview`, `/admin/feed`, `POST /admin/landlord/:lid/token` (open workspace as admin), `/app/version`.
- Brute-force lock: 5 wrong passwords → 10 min block per login ID.
- Telegram alerts to the landlord: landlord saves their Telegram ID in the app (More → Telegram alerts). They must press Start on your bot first.
- Officials scanning another landlord's card get basic details only (no vault / notes / history).
