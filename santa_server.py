"""
SANTA TOPUP — Python (Flask) backend

Self-contained server that stores data in a local db.json file (JSON storage,
no external DB — matches the style of your other bots).

What changed in this version
-----------------------------
Auto top-up is now wired to the Khmer TopUp reseller API
(https://khmer-topup.com/api/v1) instead of FazerCards:

  - Auto CHECK ID   -> GET  /check          (used by /api/check-user)
  - Auto PAYMENT    -> ABA PayWay (KHMER SYSTEM) (create-payment / check-payment)
  - Auto TOP-UP     -> POST /orders          (placed automatically the moment
                                                ABA PayWay confirms payment)
  - Delivery status -> GET  /orders/{code}   (polled by /api/check-topup-status)
  - Wallet balance  -> GET  /me              (used by /api/admin-khmertopup-balance)
  - Catalogue       -> GET  /games           (used by /api/admin-khmertopup-games)

To enable this per game:
  1. Call GET /api/admin-khmertopup-games (admin token) to pull Khmer TopUp's
     live catalogue of game `slug`s and `package_id`s priced for your account.
  2. In the admin panel (or via PUT /api/admin-games), set `khmertopup_slug`
     on the game to the matching Khmer TopUp game slug (e.g. "mobile-legends",
     "freefire-sgmy"). `has_server_id` should be true whenever that game's
     `server_label` in the catalogue is non-null.
  3. On each product, set `provider_package` to the matching Khmer TopUp
     `package_id` (an integer) from that same game's `packages` list.
  4. Set the KHMERTOPUP_API_KEY environment variable (from
     https://khmer-topup.com/settings -> API key). Top up your wallet balance
     there too — orders are charged against it.

If a game has no `khmertopup_slug` configured, or KHMERTOPUP_API_KEY is unset,
top-ups for that game simply fall back to "manual" delivery (an admin fulfils it by hand) —
nothing breaks, it just doesn't auto-deliver.

Endpoints (same paths/behavior as the original netlify/functions/*.js):
  POST /api/create-payment
  POST /api/check-payment
  POST /api/expire-payment
  GET  /api/get-home-data
  GET  /api/get-topup-data?id=<game_code>
  POST /api/check-user                 <- now does a real auto ID-check via Khmer TopUp
  GET  /api/get-stats?type=notifications
  POST /api/check-topup-status
  GET  /api/get-site-settings (public)
  GET/PUT             /api/admin-settings      (admin, header x-admin-token)
  GET/POST/PUT/DELETE /api/admin-games         (admin)
  GET/POST/PUT/DELETE /api/admin-products      (admin)
  GET/POST/PUT/DELETE /api/admin-banners       (admin)
  GET/PATCH           /api/admin-transactions  (admin)
  GET                 /api/admin-khmertopup-games   (admin — live remote catalogue)
  GET                 /api/admin-khmertopup-balance (admin — live wallet balance)

Serves:
  GET /       -> santa_topup.html (single-file frontend)
  GET /admin  -> admin_v3.html

Run:
  pip install flask requests python-dotenv cryptography --break-system-packages
  python server_v16.py
"""

import os
import json
import time
import hmac
import base64
import hashlib
import secrets
import threading
import uuid
import random
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

try:
    from dotenv import load_dotenv
    load_dotenv()  # reads .env in this folder and loads it into os.environ
except ImportError:
    pass  # falls back to real environment variables if python-dotenv isn't installed


# ---------------------------------------------------------------------------
# CryptoJS-compatible AES encryption
#
# The frontend bundle calls CryptoJS.AES.decrypt(payloadString, PASSPHRASE) on
# several endpoints (get-home-data, get-topup-data, get-stats). CryptoJS's
# passphrase-based AES uses OpenSSL's "Salted__" format: MD5-based
# EVP_BytesToKey key/iv derivation, AES-256-CBC, PKCS7 padding, base64 output.
# This must be applied server-side or the frontend silently fails to decrypt
# and the games/products/notifications never render.
# ---------------------------------------------------------------------------

FRONTEND_PAYLOAD_KEY = os.environ.get(
    "FRONTEND_PAYLOAD_KEY", "wJkxq6PKdxE+7OBOn6dk2yHA972vQ1cTUVSGhbSbtuA="
)


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    dtot = b""
    d = b""
    while len(dtot) < key_len + iv_len:
        d = hashlib.md5(d + password + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len + iv_len]


def encrypt_payload(obj) -> str:
    """Encrypt a JSON-serializable object the way CryptoJS.AES.decrypt(str, passphrase) expects."""
    if not _HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required (pip install cryptography --break-system-packages)"
        )
    plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    salt = secrets.token_bytes(8)
    key, iv = _evp_bytes_to_key(FRONTEND_PAYLOAD_KEY.encode("utf-8"), salt)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode("utf-8")


# ---------------------------------------------------------------------------
# Config (edit these, or set as real environment variables before running)
# ---------------------------------------------------------------------------

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "")
ADMIN_PANEL_TOKEN = os.environ.get("ADMIN_PANEL_TOKEN", "change-this-to-a-long-random-string")

# Admin OTP allowlist — comma-separated Telegram chat IDs of the admins who
# are allowed to open the /santa-cp-4x9k page at all, e.g. "111111,222222".
# Unlike an IP allowlist this doesn't break when someone's mobile carrier
# hands them a new IP: it's tied to who can read their own Telegram, not to
# which network they're on. See _admin_otp_* helpers below.
ADMIN_OTP_CHAT_IDS = {
    cid.strip() for cid in os.environ.get("ADMIN_CHAT_IDS", "").split(",") if cid.strip()
}

# ABA PayWay (via KHMER SYSTEM — khmer-system.com) — same integration as
# premium_shop_bot_v16.py's aba_generate_qr()/aba_check_payment().
# Profile Key + Merchant ID from khmer-system.com/operator/profile.
ABA_API_KEY = os.environ.get("ABA_API_KEY", "")
ABA_MERCHANT_ID = os.environ.get("ABA_MERCHANT_ID", "")
ABA_BASE_URL = os.environ.get("ABA_BASE_URL", "https://khmer-system.com")
ABA_CREATE_URL = os.environ.get("ABA_CREATE_URL", f"{ABA_BASE_URL}/aba-api/generate-qr")
ABA_CHECK_URL = os.environ.get("ABA_CHECK_URL", f"{ABA_BASE_URL}/aba-api/check-payment")

# Khmer TopUp reseller API (auto ID-check + auto top-up)
KHMERTOPUP_API_KEY = os.environ.get("KHMERTOPUP_API_KEY", "")
KHMERTOPUP_BASE_URL = os.environ.get("KHMERTOPUP_BASE_URL", "https://khmer-topup.com/api/v1")

# ---------------------------------------------------------------------------
# ABA PayWay integration (via KHMER SYSTEM — khmer-system.com)
# Ported from premium_shop_bot_v16.py's aba_generate_qr()/aba_check_payment().
# ---------------------------------------------------------------------------

_http = requests.Session()
_http.mount("https://", requests.adapters.HTTPAdapter(
    max_retries=requests.adapters.Retry(total=2, backoff_factor=0.5)
))
# khmer-system.com has a firewall/security plugin (Wordfence, Cloudflare, etc.)
# that blocks requests without a browser-like User-Agent — the default
# "python-requests/x.x" gets a 403 HTML page instead of JSON.
_http.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
})

_last_aba_error = ""


def aba_generate_qr(amount, username, _attempt=1):
    """POST https://khmer-system.com/aba-api/generate-qr — creates an ABA KHQR
    payment. Returns the full response dict (payment_id, qr_image, card_image,
    pay_url, expires_at...) on success, or None on failure (see _last_aba_error)."""
    global _last_aba_error
    if not ABA_API_KEY or not ABA_MERCHANT_ID:
        _last_aba_error = "ABA_API_KEY / ABA_MERCHANT_ID is not set in the server environment"
        print(f"[aba_generate_qr] {_last_aba_error}", flush=True)
        return None
    try:
        r = _http.post(
            ABA_CREATE_URL,
            json={
                "api_key": ABA_API_KEY,
                "merchant_id": ABA_MERCHANT_ID,
                "username": username,
                "amount": round(float(amount), 2),
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=20,
        )
        try:
            data = r.json()
        except ValueError:
            body = r.text.strip()
            if body.lower().startswith(("<!doctype", "<html")):
                _last_aba_error = (
                    f"HTTP {r.status_code} — server returned an HTML page (likely a firewall/WAF "
                    f"block, or a wrong endpoint URL) instead of JSON"
                )
            else:
                _last_aba_error = f"HTTP {r.status_code} (non-JSON): {body[:300]}"
            print(f"[aba_generate_qr] {_last_aba_error}", flush=True)
            if r.status_code >= 500 and _attempt < 2:
                time.sleep(1.5)
                return aba_generate_qr(amount, username, _attempt=2)
            return None
        if data.get("ok"):
            return data
        _last_aba_error = f"HTTP {r.status_code} [{data.get('code', '?')}]: {data.get('message') or data}"
        print(f"[aba_generate_qr] failed: {_last_aba_error}", flush=True)
        if r.status_code >= 500 and _attempt < 2:
            time.sleep(1.5)
            return aba_generate_qr(amount, username, _attempt=2)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        _last_aba_error = f"{type(e).__name__}: {e}"
        print(f"[aba_generate_qr] transient error: {_last_aba_error}", flush=True)
        if _attempt < 2:
            time.sleep(1.5)
            return aba_generate_qr(amount, username, _attempt=2)
    except Exception as e:  # noqa: BLE001
        _last_aba_error = f"{type(e).__name__}: {e}"
        print(f"[aba_generate_qr] error: {_last_aba_error}", flush=True)
    return None


def aba_check_payment(payment_id):
    """Checks a payment's status by payment_id — returns True if status is PAID."""
    try:
        r = _http.post(
            ABA_CHECK_URL,
            json={"api_key": ABA_API_KEY, "merchant_id": ABA_MERCHANT_ID, "payment_id": payment_id},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=10,
        )
        data = r.json()
        return bool(data.get("ok")) and str(data.get("status", "")).upper() == "PAID"
    except Exception as e:  # noqa: BLE001
        print(f"[aba_check_payment] error: {e}")
    return False


def _aba_image_src(card_image_or_qr_image):
    """khmer-system.com returns the card/QR image as either an http(s) URL, or a
    base64 string (sometimes with a 'data:image/...;base64,' prefix, sometimes
    without). Normalize to something an <img src="..."> can use directly."""
    if not card_image_or_qr_image:
        return None
    s = str(card_image_or_qr_image).strip()
    if s.lower().startswith(("http://", "https://", "data:")):
        return s
    return f"data:image/png;base64,{s}"


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)  # point this at a Render persistent disk mount in production
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "db.json")
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "db_default.json")
STATIC_DIR = BASE_DIR  # santa_topup.html + santa_admin.html live alongside this file

UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_UPLOAD_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB per upload
_db_lock = threading.Lock()

# ---------------------------------------------------------------------------
# DDoS / abuse protection
#
# This site sits behind Cloudflare (see cf-ray / server: cloudflare on live
# responses), which already absorbs volumetric/network-layer DDoS traffic.
# This layer protects against application-layer abuse: someone hammering
# endpoints that cost real money per call (Khmer TopUp check-user/place-order,
# ABA PayWay create/check-payment) or that are cheap to spam but expensive
# to read (admin-* without a valid token still does a full db_read()).
#
# Cloudflare terminates the real client IP into the CF-Connecting-IP header;
# request.remote_addr would otherwise just be Render's internal proxy IP,
# which would make every visitor share one rate-limit bucket. Prefer that
# header when present, else fall back to X-Forwarded-For, else remote_addr.
# ---------------------------------------------------------------------------
try:
    from flask_limiter import Limiter
    _HAS_LIMITER = True
except ImportError:
    _HAS_LIMITER = False


def _client_ip():
    # SECURITY: this used to trust CF-Connecting-IP and the FIRST entry of
    # X-Forwarded-For — both are attacker-controlled on this deployment
    # (Render, no Cloudflare in front), which let anyone dodge the rate
    # limiter/ban system entirely by sending a different fake IP on every
    # request. The only header value that can be trusted is the LAST entry
    # in X-Forwarded-For, which is the one Render's own proxy appends —
    # anything earlier in that list, and the CF-Connecting-IP header, is
    # whatever the client itself chose to send and must be ignored.
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.remote_addr or "unknown"


if _HAS_LIMITER:
    limiter = Limiter(
        key_func=_client_ip,
        app=app,
        default_limits=["200 per hour", "40 per minute"],
        storage_uri="memory://",  # single-instance app; swap for Redis if you scale to >1 dyno
    )

    @limiter.request_filter
    def _exempt_cors_preflight():
        return request.method == "OPTIONS"

    # -----------------------------------------------------------------------
    # Escalating auto-ban for repeat offenders
    #
    # Plain rate limiting alone just makes an attacker retry slightly slower —
    # a determined script keeps knocking forever. Anyone who keeps tripping
    # the rate limit gets banned outright for a growing period (10 min → 1
    # hour → 24 hours), checked in before_request so a banned IP is rejected
    # before touching db_read(), Khmer TopUp, or ABA PayWay — the whole point
    # is that repeat offenders cost us ~0 CPU/IO per request once banned.
    #
    # Caveat: this state lives in each gunicorn worker's own memory (not
    # shared across workers/dynos). Fine for a single Starter-plan instance;
    # move to Redis if you ever scale past one instance.
    # -----------------------------------------------------------------------
    import time as _time

    _ban_lock = threading.Lock()
    _ban_store = {}  # ip -> {"strikes": int, "banned_until": epoch, "last": epoch}
    _STRIKE_RESET_SECONDS = 3600  # a clean hour of good behavior forgives past strikes
    _BAN_DURATIONS = [600, 3600, 86400]  # 10 min, 1 hour, 24 hours (caps here)

    def _is_banned(ip):
        info = _ban_store.get(ip)
        return bool(info) and _time.time() < info.get("banned_until", 0)

    def _register_violation(ip):
        now = _time.time()
        with _ban_lock:
            info = _ban_store.setdefault(ip, {"strikes": 0, "banned_until": 0, "last": 0})
            if now - info["last"] > _STRIKE_RESET_SECONDS:
                info["strikes"] = 0
            info["strikes"] += 1
            info["last"] = now
            idx = min(info["strikes"] - 1, len(_BAN_DURATIONS) - 1)
            info["banned_until"] = now + _BAN_DURATIONS[idx]
            if len(_ban_store) > 5000:
                cutoff = now - _STRIKE_RESET_SECONDS
                for k in [k for k, v in _ban_store.items() if v["last"] < cutoff and v["banned_until"] < now]:
                    del _ban_store[k]

    @app.before_request
    def _reject_banned_ips():
        if request.method == "OPTIONS":
            return None
        if _is_banned(_client_ip()):
            return json_response({"success": False, "error": "Temporarily blocked due to repeated rate-limit violations"}, 429)
        return None
else:
    # Lets the app boot even before `pip install Flask-Limiter` — but log loudly,
    # since running without this in production means no abuse protection at all.
    print("!! Flask-Limiter not installed — rate limiting is DISABLED. Run: pip install Flask-Limiter")

    class _NoopLimiter:
        def limit(self, *a, **kw):
            def deco(fn):
                return fn
            return deco

        def exempt(self, fn):
            return fn

    limiter = _NoopLimiter()

    def _register_violation(ip):
        pass  # no rate limiting installed, so nothing to escalate


# ---------------------------------------------------------------------------
# Site-wide private access (optional)
#
# Renders the WHOLE site (storefront + API, not just /admin) behind an HTTP
# Basic Auth prompt. The public URL still resolves — Render doesn't offer a
# truly hidden URL on its free/Starter tiers — but nothing behind it loads
# without the shared username/password, so a stranger who finds the link
# can't see the shop, place orders, or hit any API route.
#
# Enable by setting SITE_PRIVATE=true plus SITE_USERNAME / SITE_PASSWORD in
# your environment. Leave SITE_PRIVATE unset (or "false") to keep the site
# public — nothing below runs in that case, so existing deployments are
# unaffected until you opt in.
# ---------------------------------------------------------------------------

SITE_PRIVATE = os.environ.get("SITE_PRIVATE", "false").strip().lower() == "true"
SITE_USERNAME = os.environ.get("SITE_USERNAME", "")
SITE_PASSWORD = os.environ.get("SITE_PASSWORD", "")

if SITE_PRIVATE:
    if not SITE_USERNAME or not SITE_PASSWORD:
        print("!! SITE_PRIVATE=true but SITE_USERNAME/SITE_PASSWORD is not set — refusing to boot open.")
        raise SystemExit("Set SITE_USERNAME and SITE_PASSWORD before enabling SITE_PRIVATE.")

    @app.before_request
    def _require_site_login():
        if request.method == "OPTIONS":
            return None  # CORS preflight has no credentials to check — let it through
        auth = request.authorization
        ok = bool(auth) and hmac.compare_digest(auth.username or "", SITE_USERNAME) \
            and hmac.compare_digest(auth.password or "", SITE_PASSWORD)
        if not ok:
            resp = json_response({"success": False, "error": "Authentication required"}, 401)
            resp.headers["WWW-Authenticate"] = 'Basic realm="SANTA TOPUP (private)"'
            return resp
        return None


# ---------------------------------------------------------------------------
# Tiny JSON "database" (mirrors your usual db.json pattern)
# ---------------------------------------------------------------------------

def _seed_from_defaults(data):
    """Merge any games/products/banners from db_default.json into an EXISTING db.json
    that are missing (matched by 'code' for games/products, 'image_url' for banners).
    This lets you add catalog items by editing db_default.json and redeploying, even
    if db.json already exists on disk (e.g. from earlier admin-panel entries) — so a
    stale/pre-existing db.json never silently blocks your new baked-in entries."""
    try:
        with open(DEFAULT_DB_PATH, "r", encoding="utf-8") as f:
            defaults = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    changed = False

    existing_game_codes = {g.get("code") for g in data.get("games", [])}
    for g in defaults.get("games", []):
        if g.get("code") not in existing_game_codes:
            new_row = dict(g)
            new_row["id"] = next_id(data, "games")
            data["games"].append(new_row)
            existing_game_codes.add(g.get("code"))
            changed = True

    existing_products = {(p.get("game_code"), p.get("name")) for p in data.get("products", [])}
    for p in defaults.get("products", []):
        key = (p.get("game_code"), p.get("name"))
        if key not in existing_products:
            new_row = dict(p)
            new_row["id"] = next_id(data, "products")
            data["products"].append(new_row)
            existing_products.add(key)
            changed = True

    existing_banner_urls = {b.get("image_url") for b in data.get("banners", [])}
    for b in defaults.get("banners", []):
        if b.get("image_url") not in existing_banner_urls:
            new_row = dict(b)
            new_row["id"] = next_id(data, "banners")
            data["banners"].append(new_row)
            existing_banner_urls.add(b.get("image_url"))
            changed = True

    return changed


# Every top-level table this app reads/writes, with the empty value it should
# start as. Both the "no db.json yet" fallback and any existing db.json that
# predates a newer table (e.g. site_settings, added after the file was first
# created) are backfilled against this — otherwise a plain dict lookup like
# db_read()["site_settings"] raises KeyError and the route 500s, which is
# exactly what happened here: the old fallback schema had a stale "orders"
# key that nothing reads (the real table is "transactions") and never had
# "site_settings" at all.
SCHEMA_DEFAULTS = {
    "games": [],
    "products": [],
    "banners": [],
    "transactions": [],
    "site_settings": {},
    "next_ids": {},
}


def _ensure_schema(data):
    """Backfill any missing top-level keys in place. Returns True if it changed anything."""
    changed = False
    for key, default in SCHEMA_DEFAULTS.items():
        if key not in data:
            data[key] = [] if isinstance(default, list) else dict(default)
            changed = True
    return changed


def _load_db():
    if not os.path.exists(DB_PATH):
        if os.path.exists(DEFAULT_DB_PATH):
            with open(DEFAULT_DB_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            # db_default.json wasn't part of this deploy — start from an
            # empty-but-valid schema instead of crashing (this is the exact
            # FileNotFoundError PVH TOPUP hit on its first deploy).
            print("WARNING: db_default.json not found — starting with an empty database.")
            data = {}
        _ensure_schema(data)
        _save_db(data)
        return data
    with open(DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    changed = _seed_from_defaults(data)
    if _ensure_schema(data):
        changed = True
    if changed:
        _save_db(data)
    return data


def _save_db(data):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def db_read():
    with _db_lock:
        return _load_db()


def db_write(mutate_fn):
    """mutate_fn(data) -> result; runs under lock, persists, returns result of mutate_fn"""
    with _db_lock:
        data = _load_db()
        result = mutate_fn(data)
        _save_db(data)
        return result


def next_id(data, table):
    nid = data["next_ids"].get(table, 1)
    data["next_ids"][table] = nid + 1
    return nid


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers (mirror _utils.js)
# ---------------------------------------------------------------------------

def json_response(payload, status=200):
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def notify_admin(text):
    if not TELEGRAM_BOT_TOKEN or not ADMIN_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": ADMIN_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
    except requests.RequestException as e:
        print("Telegram notify failed:", e)


def find_by_id(rows, id_value, key="id"):
    for row in rows:
        if str(row.get(key)) == str(id_value):
            return row
    return None


def find_game(data, game_code):
    return next((g for g in data.get("games", []) if g.get("code") == game_code), None)


# ---------------------------------------------------------------------------
# Admin page gate: Telegram OTP + signed device cookie
#
# /santa-cp-4x9k first checks for a valid "santa_admin_device" cookie. If
# missing/invalid it serves a small self-contained gate page (not
# santa_admin.html) asking for a 6-digit code; the code is requested via
# /api/admin-request-otp (sent to every chat id in ADMIN_OTP_CHAT_IDS) and
# checked via /api/admin-verify-otp, which sets the cookie on success.
#
# The cookie is a stateless HMAC (signed with ADMIN_PANEL_TOKEN) so it keeps
# working across server restarts/redeploys even though the in-memory OTP
# store does not — the OTP itself only needs to survive the ~5 minutes
# between requesting and entering it.
# ---------------------------------------------------------------------------
_otp_store = {}  # otp_id -> {"code": "123456", "expires": epoch}
_OTP_TTL_SECONDS = 5 * 60
_DEVICE_COOKIE_NAME = "santa_admin_device"
_DEVICE_COOKIE_TTL_SECONDS = 90 * 24 * 3600  # 90 days


def _device_cookie_secret():
    return ADMIN_PANEL_TOKEN.encode("utf-8")


def _sign_device_cookie(expires_at):
    payload = str(int(expires_at))
    sig = hmac.new(_device_cookie_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _device_cookie_valid(value):
    if not value or "." not in value:
        return False
    payload, _, sig = value.partition(".")
    expected = hmac.new(_device_cookie_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        return int(payload) > time.time()
    except ValueError:
        return False


def _send_telegram_to(chat_id, text):
    if not TELEGRAM_BOT_TOKEN:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
    except requests.RequestException as e:
        print("Telegram OTP send failed:", e)


_ADMIN_GATE_HTML = """<!doctype html>
<html lang="km"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SANTA TOPUP — Admin</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#F6F1E4;font-family:sans-serif;color:#1C1B19;padding:20px;}
.card{background:#FFFDF6;border:1.5px solid #1C1B19;border-radius:4px;padding:36px 30px;
  width:100%;max-width:320px;text-align:center;box-shadow:3px 3px 0 #B9AF90;}
h1{font-size:20px;margin:0 0 6px;}
p{color:#6B6558;font-size:12.5px;margin:0 0 20px;}
input{width:100%;padding:12px;border-radius:3px;border:1.5px solid #1C1B19;background:#F6F1E4;
  color:#1C1B19;font-size:20px;text-align:center;letter-spacing:6px;margin-bottom:12px;box-sizing:border-box;}
button{width:100%;padding:12px;border-radius:3px;border:1.5px solid #1C1B19;background:#1E5AA8;
  color:#fff;font-weight:700;font-size:14px;cursor:pointer;margin-bottom:8px;}
button.secondary{background:#F6F1E4;color:#1C1B19;}
.err{color:#B23A2E;font-size:12.5px;min-height:16px;margin-top:6px;}
</style></head>
<body><div class="card">
<h1>SANTA TOPUP Admin</h1>
<p id="step1">ចុចខាងក្រោមដើម្បីផ្ញើកូដទៅ Telegram</p>
<div id="requestView">
  <button onclick="requestOtp()">ផ្ញើកូដទៅ Telegram</button>
</div>
<div id="verifyView" style="display:none">
  <input id="code" maxlength="6" inputmode="numeric" placeholder="000000">
  <button onclick="verifyOtp()">បញ្ជាក់</button>
  <button class="secondary" onclick="requestOtp()">ផ្ញើកូដម្តងទៀត</button>
</div>
<div class="err" id="err"></div>
</div>
<script>
let otpId = null;
async function requestOtp(){
  document.getElementById('err').textContent = '';
  const res = await fetch('/api/admin-request-otp', {method:'POST'});
  const data = await res.json();
  if(!data.success){ document.getElementById('err').textContent = data.error || 'បរាជ័យ'; return; }
  otpId = data.otp_id;
  document.getElementById('requestView').style.display = 'none';
  document.getElementById('verifyView').style.display = 'block';
  document.getElementById('step1').textContent = 'វាយកូដ 6 ខ្ទង់ដែលទទួលបានក្នុង Telegram';
}
async function verifyOtp(){
  const code = document.getElementById('code').value.trim();
  const res = await fetch('/api/admin-verify-otp', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({otp_id: otpId, code})
  });
  const data = await res.json();
  if(!data.success){ document.getElementById('err').textContent = data.error || 'កូដមិនត្រឹមត្រូវ'; return; }
  location.reload();
}
</script></body></html>"""


def require_admin():
    """Returns None if authorized, else a Flask response to short-circuit with."""
    if not ADMIN_PANEL_TOKEN:
        return json_response({"success": False, "error": "ADMIN_PANEL_TOKEN is not configured on the server"}, 500)
    provided = request.headers.get("x-admin-token") or request.headers.get("X-Admin-Token")
    if not provided:
        return json_response({"success": False, "error": "Missing admin token"}, 401)
    if not hmac.compare_digest(str(provided), str(ADMIN_PANEL_TOKEN)):
        return json_response({"success": False, "error": "Invalid admin token"}, 401)
    return None


# ---------------------------------------------------------------------------
# Khmer TopUp integration (auto ID-check + auto top-up)
# https://khmer-topup.com/api-docs
#
# Auth: `Authorization: Bearer <key>` (or `X-API-Key: <key>`) on every call.
# Every game has one `slug` (from GET /games) and each of its packages has one
# integer `package_id` — that's the whole mapping, much flatter than FazerCards'
# two separate category namespaces.
# ---------------------------------------------------------------------------

class KhmerTopUpError(Exception):
    """Raised with the provider's own message where possible (see _khmertopup_error_message)."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _khmertopup_headers(extra=None):
    headers = {"Authorization": f"Bearer {KHMERTOPUP_API_KEY}", "Content-Type": "application/json"}
    if extra:
        headers.update(extra)
    return headers


_KHMERTOPUP_ERROR_MESSAGES = {
    400: "Missing or invalid field",
    401: "Invalid or missing Khmer TopUp API key",
    402: "Insufficient Khmer TopUp wallet balance — top up your reseller wallet",
    404: "Unknown game, package, or order on Khmer TopUp",
    409: "Order reference already used for a different order",
    413: "Request body too large",
    429: "Khmer TopUp rate limit exceeded — slow down",
}


def _khmertopup_error_message(res):
    try:
        body = res.json()
        if isinstance(body, dict) and body.get("error"):
            return str(body["error"])
    except ValueError:
        pass
    return _KHMERTOPUP_ERROR_MESSAGES.get(res.status_code, f"Khmer TopUp error ({res.status_code})")


def _khmertopup_request(method, path, **kwargs):
    if not KHMERTOPUP_API_KEY:
        raise KhmerTopUpError("KHMERTOPUP_API_KEY is not set")
    res = requests.request(
        method, f"{KHMERTOPUP_BASE_URL}{path}", headers=_khmertopup_headers(kwargs.pop("extra_headers", None)),
        timeout=kwargs.pop("timeout", 15), **kwargs,
    )
    if res.status_code == 429:
        raise KhmerTopUpError(_khmertopup_error_message(res), status_code=429)
    if not res.ok:
        raise KhmerTopUpError(_khmertopup_error_message(res), status_code=res.status_code)
    try:
        return res.json()
    except ValueError:
        raise KhmerTopUpError(f"Bad response from Khmer TopUp ({res.status_code})", status_code=res.status_code)


def khmertopup_get_balance():
    """GET /me -> {username, role, balance, currency}"""
    return _khmertopup_request("GET", "/me")


# Full games+packages catalogue, cached in memory per process — refresh by
# restarting the server or hitting /api/admin-khmertopup-games (which bypasses
# this cache) after Khmer TopUp adds/reprices a game.
_khmertopup_games_cache = None


def khmertopup_get_games(force=False):
    """GET /games -> {games: [{slug, name, id_label, server_label, packages:[...]}]}"""
    global _khmertopup_games_cache
    if _khmertopup_games_cache is not None and not force:
        return _khmertopup_games_cache
    data = _khmertopup_request("GET", "/games")
    _khmertopup_games_cache = data
    return data


def khmertopup_check(slug, player_id, server_id=None):
    """Auto CHECK ID: GET /check -> {result: valid|invalid|incomplete|unknown, nickname?, message?}"""
    params = {"slug": slug, "player_id": player_id}
    if server_id not in (None, ""):
        params["server_id"] = server_id
    return _khmertopup_request("GET", "/check", params=params)


def khmertopup_place_order(package_id, player_id, server_id, reference):
    """Auto TOP-UP: POST /orders -> {order_code, status, price, balance, idempotent, ...}
    `reference` is our own trx_id, used as Khmer TopUp's idempotency key — retrying
    with the same reference returns the original order instead of charging twice."""
    body = {"package_id": int(package_id), "player_id": str(player_id), "reference": str(reference)}
    if server_id not in (None, ""):
        body["server_id"] = str(server_id)
    return _khmertopup_request("POST", "/orders", json=body, timeout=20)


def khmertopup_get_order(order_code):
    """Poll delivery status: GET /orders/{order_code} ->
    {order_code, status: processing|completed|refunded, ...}"""
    return _khmertopup_request("GET", f"/orders/{order_code}")


# ---------------------------------------------------------------------------
# Static file serving — single-file frontend + admin panel
# ---------------------------------------------------------------------------

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/manifest.json")
def serve_manifest():
    return send_from_directory(STATIC_DIR, "manifest.json")


@app.route("/icon-192.png")
def serve_icon_192():
    return send_from_directory(STATIC_DIR, "icon-192.png")


@app.route("/icon-512.png")
def serve_icon_512():
    return send_from_directory(STATIC_DIR, "icon-512.png")


@app.route("/api/admin-upload", methods=["POST", "OPTIONS"])
@limiter.limit("20 per minute")
def admin_upload():
    """Accepts a real image file (multipart/form-data, field name 'file') from the admin
    panel and returns a URL under /uploads/... — this is what lets the admin panel offer
    an actual upload button instead of requiring you to paste an image link."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if "file" not in request.files:
        return json_response({"success": False, "error": "No file provided"}, 400)
    file = request.files["file"]
    if not file or file.filename == "":
        return json_response({"success": False, "error": "No file selected"}, 400)

    ext = secure_filename(file.filename).rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return json_response(
            {"success": False, "error": f"File type not allowed (use: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))})"},
            400,
        )

    filename = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, filename))
    url = f"/uploads/{filename}"
    return json_response({"success": True, "url": url})


@app.route("/")
def serve_index():
    return send_from_directory(STATIC_DIR, "santa_topup.html")


@app.route("/terms")
@app.route("/terms/")
def serve_terms():
    try:
        return send_from_directory(STATIC_DIR, "terms.html")
    except FileNotFoundError:
        return json_response({"success": False, "error": "terms.html not found — upload it alongside server_v16.py"}, 404)


@app.route("/privacy")
@app.route("/privacy/")
def serve_privacy():
    try:
        return send_from_directory(STATIC_DIR, "privacy.html")
    except FileNotFoundError:
        return json_response({"success": False, "error": "privacy.html not found — upload it alongside server_v16.py"}, 404)


@app.route("/santa-cp-4x9k")
@app.route("/santa-cp-4x9k/")
@limiter.limit("15 per minute")
def serve_admin():
    if not _device_cookie_valid(request.cookies.get(_DEVICE_COOKIE_NAME)):
        return _ADMIN_GATE_HTML
    try:
        return send_from_directory(STATIC_DIR, "santa_admin.html")
    except FileNotFoundError:
        # santa_admin.html wasn't part of this deploy bundle — every /api/admin-*
        # route above still works fine with curl/Postman/x-admin-token in the
        # meantime, this just avoids a raw 500 if someone clicks /admin.
        return json_response(
            {"success": False, "error": "santa_admin.html not found — upload the admin panel HTML alongside server_v16.py"},
            404,
        )


@app.route("/api/admin-request-otp", methods=["POST"])
@limiter.limit("5 per minute")
def admin_request_otp():
    if not ADMIN_OTP_CHAT_IDS:
        return json_response(
            {"success": False, "error": "ADMIN_CHAT_IDS is not configured on the server"}, 500
        )
    if not TELEGRAM_BOT_TOKEN:
        return json_response(
            {"success": False, "error": "TELEGRAM_BOT_TOKEN is not configured on the server"}, 500
        )
    otp_id = uuid.uuid4().hex
    code = f"{secrets.randbelow(1_000_000):06d}"
    _otp_store[otp_id] = {"code": code, "expires": time.time() + _OTP_TTL_SECONDS}
    # prune old entries so this dict doesn't grow forever
    now = time.time()
    for k in [k for k, v in _otp_store.items() if v["expires"] < now]:
        _otp_store.pop(k, None)
    for chat_id in ADMIN_OTP_CHAT_IDS:
        _send_telegram_to(chat_id, f"🔐 SANTA TOPUP admin login code: `{code}`\nឆាប់ផុតកំណត់ក្នុង 5 នាទី។")
    return json_response({"success": True, "otp_id": otp_id})


@app.route("/api/admin-verify-otp", methods=["POST"])
@limiter.limit("10 per minute")
def admin_verify_otp():
    body = request.get_json(silent=True) or {}
    otp_id = str(body.get("otp_id") or "")
    code = str(body.get("code") or "").strip()
    entry = _otp_store.get(otp_id)
    if not entry or entry["expires"] < time.time():
        return json_response({"success": False, "error": "កូដផុតកំណត់ — សូមស្នើសុំកូដថ្មី"}, 400)
    if not hmac.compare_digest(code, entry["code"]):
        return json_response({"success": False, "error": "កូដមិនត្រឹមត្រូវ"}, 401)
    _otp_store.pop(otp_id, None)
    expires_at = time.time() + _DEVICE_COOKIE_TTL_SECONDS
    resp = json_response({"success": True})
    resp.set_cookie(
        _DEVICE_COOKIE_NAME,
        _sign_device_cookie(expires_at),
        max_age=_DEVICE_COOKIE_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return resp


# ---------------------------------------------------------------------------
# Public API — payment flow
# ---------------------------------------------------------------------------

@app.route("/api/create-payment", methods=["POST", "OPTIONS"])
@limiter.limit("6 per minute")
def create_payment():
    if request.method == "OPTIONS":
        return json_response({})

    body = request.get_json(silent=True) or {}
    user_id = body.get("userId")
    zone_id = body.get("zoneId")
    game_code = body.get("gameCode")
    product_id = body.get("productId")

    if not game_code or not product_id:
        return json_response({"success": False, "error": "Missing required fields"}, 400)

    # Trust nothing the client says about price. A shared "signing secret" can't
    # protect this anyway — anything shipped in the frontend bundle is visible to
    # anyone who opens dev tools. The real protection is to never accept a client-
    # supplied amount at all: look the product up ourselves and charge exactly
    # what's stored in the database for it.
    data = db_read()
    product = find_by_id(data["products"], product_id)
    if product is None or _norm_code(product.get("game_code")) != _norm_code(game_code):
        return json_response({"success": False, "error": "Product not found"}, 404)

    if not user_id:
        return json_response({"success": False, "error": "Missing required fields"}, 400)

    try:
        amount = float(product.get("price") or 0)
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        return json_response({"success": False, "error": "Invalid product price"}, 400)

    trx_id = f"PVH{int(time.time() * 1000)}{secrets.randbelow(1000)}"

    if not ABA_API_KEY or not ABA_MERCHANT_ID:
        return json_response({"success": False, "error": "ABA_API_KEY / ABA_MERCHANT_ID is not configured on the server"}, 500)

    # ABA PayWay's "username" is just a display label on the payment card —
    # the in-game player ID doubles fine as one here (no Telegram handle to use).
    aba_data = aba_generate_qr(amount, str(user_id))
    if not aba_data:
        print("aba_generate_qr failed:", _last_aba_error)
        return json_response({"success": False, "error": "Failed to generate QR"}, 500)

    payment_id = aba_data.get("payment_id")
    if not payment_id:
        print("aba_generate_qr returned no payment_id:", aba_data)
        return json_response({"success": False, "error": "Failed to generate QR"}, 500)

    reference = payment_id
    qr_image = _aba_image_src(aba_data.get("card_image") or aba_data.get("qr_image"))
    pay_url = aba_data.get("pay_url")

    def _mutate(d):
        d["transactions"].append({
            "trx_id": trx_id,
            "reference": reference,
            "user_id": user_id,
            "zone_id": zone_id,
            "game_code": game_code,
            "product_id": product_id,
            "amount": float(amount),
            "status": "pending",
            "delivery_status": None,
            "delivery_error": None,
            "delivery_code": None,
            "provider_order_id": None,
            "created_at": now_iso(),
            "paid_at": None,
        })

    db_write(_mutate)
    return json_response({"success": True, "trx_id": trx_id, "qr_image": qr_image, "pay_url": pay_url})


@app.route("/api/check-payment", methods=["POST", "OPTIONS"])
@limiter.limit("15 per minute")
def check_payment():
    if request.method == "OPTIONS":
        return json_response({})

    body = request.get_json(silent=True) or {}
    trx_id = body.get("trx_id")
    if not trx_id:
        return json_response({"paid": False, "error": "Missing trx_id"}, 400)

    data = db_read()
    order = find_by_id(data["transactions"], trx_id, key="trx_id")
    if not order:
        return json_response({"paid": False, "error": "Order not found"}, 404)
    if order["status"] == "paid":
        return json_response({"paid": True, "data": order})
    if order["status"] == "expired":
        return json_response({"paid": False, "expired": True})

    if not ABA_API_KEY or not ABA_MERCHANT_ID:
        return json_response({"paid": False, "error": "ABA_API_KEY / ABA_MERCHANT_ID is not configured on the server"}, 500)

    try:
        is_paid = aba_check_payment(order["reference"])
    except Exception as e:  # noqa: BLE001
        print("aba_check_payment request failed:", e)
        return json_response({"paid": False, "error": "Server error"}, 500)

    if not is_paid:
        return json_response({"paid": False})

    # Mark paid + run auto top-up (Khmer TopUp) + notify admin
    def _mutate(d):
        o = find_by_id(d["transactions"], trx_id, key="trx_id")
        o["status"] = "paid"
        o["paid_at"] = now_iso()

        product = find_by_id(d["products"], o["product_id"])
        game = find_game(d, o["game_code"])
        kt_slug = (game or {}).get("khmertopup_slug")
        kt_package_id = (product or {}).get("provider_package")  # Khmer TopUp package_id lives here

        delivery_status = "manual"
        delivery_error = None
        provider_order_id = None
        delivery_code = None

        can_attempt = KHMERTOPUP_API_KEY and kt_slug and kt_package_id

        if can_attempt:
            try:
                # trx_id doubles as Khmer TopUp's `reference` (idempotency key): safe
                # to retry this exact call later (e.g. from the admin dashboard)
                # without double-charging the wallet or double-delivering.
                kt_res = khmertopup_place_order(
                    kt_package_id, o["user_id"], o.get("zone_id"), reference=o["trx_id"]
                )
                provider_order_id = kt_res.get("order_code")
                kt_status = str(kt_res.get("status", "")).lower()
                delivery_status = "delivered" if kt_status == "completed" else "processing"
            except KhmerTopUpError as e:
                delivery_status = "failed"
                delivery_error = str(e)
            except (TypeError, ValueError) as e:
                delivery_status = "failed"
                delivery_error = f"Invalid package id in provider_package: {e}"
            except Exception as e:  # noqa: BLE001
                print("Khmer TopUp order failed:", e)
                delivery_status = "failed"
                delivery_error = str(e)

        o["provider_order_id"] = provider_order_id
        o["delivery_status"] = delivery_status
        o["delivery_error"] = delivery_error
        o["delivery_code"] = delivery_code
        return o, delivery_status, provider_order_id, delivery_error

    order_after, delivery_status, provider_order_id, delivery_error = db_write(_mutate)

    if delivery_status == "processing":
        delivery_line = f"⏳ Auto top-up submitted to Khmer TopUp (order {provider_order_id}) — awaiting confirmation"
    elif delivery_status == "delivered":
        delivery_line = f"💎 Auto top-up delivered instantly (order {provider_order_id})"
    elif delivery_status == "failed":
        delivery_line = f"⚠️ *AUTO TOP-UP FAILED*: {delivery_error}\n👉 Please deliver manually"
    else:
        delivery_line = "👤 No Khmer TopUp mapping for this product — please deliver manually"

    zone_part = f" ({order_after['zone_id']})" if order_after.get("zone_id") else ""
    notify_admin(
        "✅ *PAYMENT CONFIRMED (ABA PayWay)*\n"
        "--------------------------\n"
        f"🎮 Game: {order_after['game_code']}\n"
        f"🆔 User ID: {order_after['user_id']}{zone_part}\n"
        f"💎 Product: {order_after['product_id']}\n"
        f"💰 Amount: ${order_after['amount']}\n"
        f"🧾 Ref: {order_after['reference']}\n"
        "--------------------------\n"
        f"{delivery_line}"
    )

    return json_response({"paid": True, "data": {**order_after, "status": "paid", "delivery_status": delivery_status}})


@app.route("/api/expire-payment", methods=["POST", "OPTIONS"])
def expire_payment():
    if request.method == "OPTIONS":
        return json_response({})

    body = request.get_json(silent=True) or {}
    trx_id = body.get("trx_id")
    if not trx_id:
        return json_response({"success": False, "error": "Missing trx_id"}, 400)

    def _mutate(d):
        o = find_by_id(d["transactions"], trx_id, key="trx_id")
        if o and o["status"] != "paid":
            o["status"] = "expired"

    db_write(_mutate)
    return json_response({"success": True})


@app.route("/api/check-topup-status", methods=["POST", "OPTIONS"])
@limiter.limit("15 per minute")
def check_topup_status():
    if request.method == "OPTIONS":
        return json_response({})

    body = request.get_json(silent=True) or {}
    trx_id = body.get("trx_id")
    if not trx_id:
        return json_response({"error": "Missing trx_id"}, 400)

    data = db_read()
    order = find_by_id(data["transactions"], trx_id, key="trx_id")
    if not order:
        return json_response({"error": "Order not found"}, 404)

    if order.get("delivery_status") != "processing" or not order.get("provider_order_id"):
        return json_response({
            "delivery_status": order.get("delivery_status"),
            "delivery_error": order.get("delivery_error"),
        })

    try:
        kt_order = khmertopup_get_order(order["provider_order_id"])
    except KhmerTopUpError as e:
        print("check-topup-status error:", e)
        return json_response({"error": "Server error"}, 500)
    except Exception as e:  # noqa: BLE001
        print("check-topup-status error:", e)
        return json_response({"error": "Server error"}, 500)

    provider_status = str(kt_order.get("status", "")).lower()
    new_status = order["delivery_status"]
    new_error = order.get("delivery_error")
    new_code = order.get("delivery_code")

    if provider_status == "completed":
        new_status = "delivered"
    elif provider_status == "refunded":
        # Khmer TopUp auto-refunds a bad ID or supplier failure — nothing left to
        # deliver, and the wallet was already credited back on their side.
        new_status = "failed"
        new_error = "Khmer TopUp refunded the order (invalid account or supplier failure)"

    if new_status != order["delivery_status"] or new_code != order.get("delivery_code"):
        def _mutate(d):
            o = find_by_id(d["transactions"], trx_id, key="trx_id")
            o["delivery_status"] = new_status
            o["delivery_error"] = new_error
            o["delivery_code"] = new_code

        db_write(_mutate)

        zone_part = f" ({order['zone_id']})" if order.get("zone_id") else ""
        if new_status == "delivered":
            code_part = f"\nCode: {new_code}" if new_code else ""
            notify_admin(
                f"💎 *AUTO TOP-UP DELIVERED*\n{order['game_code']} / {order['user_id']}{zone_part}\nRef: {order['reference']}{code_part}"
            )
        elif new_status == "failed":
            notify_admin(
                f"⚠️ *AUTO TOP-UP FAILED* after processing\n{order['game_code']} / {order['user_id']}\n"
                f"Ref: {order['reference']}\nReason: {new_error}\n👉 Please deliver manually"
            )

    return json_response({"delivery_status": new_status, "delivery_error": new_error, "delivery_code": new_code})


# ---------------------------------------------------------------------------
# Public API — page data
# ---------------------------------------------------------------------------

@app.route("/api/get-home-data", methods=["GET", "OPTIONS"])
def get_home_data():
    if request.method == "OPTIONS":
        return json_response({})
    data = db_read()
    payload = encrypt_payload({"games": data["games"], "banners": data["banners"]})
    return json_response({"success": True, "payload": payload})


def _norm_code(v):
    return str(v or "").strip().lower()


@app.route("/api/get-topup-data", methods=["GET", "OPTIONS"])
def get_topup_data():
    if request.method == "OPTIONS":
        return json_response({})

    game_code = request.args.get("id")
    if not game_code:
        return json_response({"success": False, "error": "Missing id"}, 400)

    data = db_read()
    target = _norm_code(game_code)
    game = next((g for g in data["games"] if _norm_code(g.get("code")) == target), None)
    if game is None:
        return json_response({"success": False, "error": "Game not found"}, 404)

    products = [p for p in data["products"] if _norm_code(p.get("game_code")) == target]

    # Defensive: coerce legacy string prices (saved before the numeric-price fix) so the
    # frontend's price.toFixed(2) doesn't crash and silently blank out the whole package list.
    for p in products:
        if p.get("price") not in (None, ""):
            try:
                p["price"] = float(p["price"])
            except (TypeError, ValueError):
                p["price"] = 0
        # Defensive: frontend hides any product whose "section" isn't exactly
        # "recommend" or "normal" — old rows (added before this field existed)
        # would otherwise vanish from the site even though they're in the DB.
        if p.get("section") not in ("recommend", "normal"):
            p["section"] = "normal"

    # Public-safe view only: cost_usd (wholesale cost, used for margin math in the
    # admin panel) and provider_package (the Khmer TopUp package_id) must never reach
    # the browser — the frontend's AES key/passphrase is public, so anything put
    # in this payload is effectively readable by anyone, not just "hidden" by
    # decryption. Whitelist exactly what the storefront needs to render a card.
    PUBLIC_PRODUCT_FIELDS = ("id", "game_code", "name", "price", "image_url", "section")
    public_products = [{f: p.get(f) for f in PUBLIC_PRODUCT_FIELDS} for p in products]

    payload = encrypt_payload({"game": game, "products": public_products})
    return json_response({"success": True, "payload": payload})


@app.route("/api/check-user", methods=["POST", "OPTIONS"])
@limiter.limit("10 per minute;100 per hour")
def check_user():
    """Auto CHECK ID — validates the player ID against Khmer TopUp before checkout
    so the customer sees their in-game nickname and typos get caught early."""
    if request.method == "OPTIONS":
        return json_response({})

    body = request.get_json(silent=True) or {}
    game_code = body.get("gameCode")
    user_id = body.get("userId")
    zone_id = body.get("zoneId")
    if not game_code or not user_id:
        # DEBUG: log the raw body so we can see what keys the frontend actually sends.
        print("check-user MISSING FIELDS — raw body received:", body)
        return json_response({"success": False, "error": "Missing fields"}, 400)

    data = db_read()
    game = find_game(data, game_code)
    kt_slug = (game or {}).get("khmertopup_slug")

    if not KHMERTOPUP_API_KEY or not kt_slug:
        # No Khmer TopUp key/slug configured yet — don't block checkout, just skip the auto-check.
        return json_response({"success": True, "name": None})

    try:
        result = khmertopup_check(kt_slug, user_id, zone_id)
    except KhmerTopUpError as e:
        print("khmertopup check failed:", e)
        return json_response({"success": True, "name": None})
    except Exception as e:  # noqa: BLE001
        print("khmertopup check failed:", e)
        return json_response({"success": True, "name": None})

    outcome = result.get("result")
    if outcome == "valid":
        return json_response({"success": True, "name": result.get("nickname")})
    if outcome == "unknown":
        # Verification unavailable on Khmer TopUp's side — a bad ID here is
        # auto-refunded on order, so don't block checkout over it.
        return json_response({"success": True, "name": None})
    if outcome == "incomplete":
        return json_response({"success": False, "error": result.get("message") or "Missing field", "name": None})

    return json_response({"success": False, "error": "Player ID not found", "name": None})


@app.route("/api/get-stats", methods=["GET", "OPTIONS"])
def get_stats():
    if request.method == "OPTIONS":
        return json_response({})
    stat_type = request.args.get("type", "notifications")
    data = db_read()
    paid = [t for t in data["transactions"] if t.get("status") == "paid"]
    paid_sorted = sorted(paid, key=lambda t: t.get("created_at") or "", reverse=True)[:10]
    slim = [
        {"user_id": t["user_id"], "game_code": t["game_code"], "amount": t["amount"], "created_at": t["created_at"]}
        for t in paid_sorted
    ]
    payload = encrypt_payload(slim)
    return json_response({"success": True, "type": stat_type, "payload": payload})


@app.route("/api/my-orders", methods=["GET", "OPTIONS"])
@limiter.limit("20 per minute")
def my_orders():
    if request.method == "OPTIONS":
        return json_response({})

    user_id = (request.args.get("userId") or "").strip()
    if not user_id:
        return json_response({"success": False, "error": "Missing userId"}, 400)

    data = db_read()
    products_by_id = {p["id"]: p for p in data["products"]}
    games_by_code = {g["code"]: g for g in data["games"]}

    # Player ID is the only identifier this site has (no login system) — same trust
    # model as /api/check-user. Anyone who knows a player ID can see its order
    # history, same as anyone who knows it can already validate/target it for a
    # top-up. Rate-limited above so it can't be used to bulk-scrape all IDs.
    matches = [t for t in data["transactions"] if str(t.get("user_id")) == user_id]
    matches.sort(key=lambda t: t.get("created_at") or "", reverse=True)
    matches = matches[:20]

    orders = []
    for t in matches:
        product = products_by_id.get(t.get("product_id"))
        game = games_by_code.get(t.get("game_code"))
        orders.append({
            "trx_id": t.get("trx_id"),
            "game_name": (game or {}).get("name") or t.get("game_code"),
            "product_name": (product or {}).get("name") or "",
            "amount": t.get("amount"),
            "status": t.get("status"),
            "delivery_status": t.get("delivery_status"),
            "delivery_code": t.get("delivery_code"),
            "created_at": t.get("created_at"),
            "paid_at": t.get("paid_at"),
        })
    return json_response({"success": True, "orders": orders})


@app.route("/api/get-site-settings", methods=["GET", "OPTIONS"])
def get_site_settings():
    if request.method == "OPTIONS":
        return json_response({})
    s = db_read()["site_settings"]
    return json_response({
        "success": True,
        "settings": {
            "SITE_NAME": s.get("site_name") or "SANTA TOPUP",
            "FOOTER_NAME": s.get("footer_name") or "SANTA TOPUP",
            "LOGO_URL": s.get("logo_url") or "",
            "ADMIN_TELEGRAM_LINK": s.get("admin_telegram_link") or "",
            "ADMIN_TELEGRAM_NAME": s.get("admin_telegram_name") or "",
            "FACEBOOK_LINK": s.get("facebook_link") or "",
            "TIKTOK_LINK": s.get("tiktok_link") or "",
            "FOOTER_DESC": s.get("footer_desc") or "",
            "COPYRIGHT": s.get("copyright") or "",
            "KHQR_LOGO_URL": s.get("khqr_logo_url") or "",
            "ABA_LOGO_URL": s.get("aba_logo_url") or "",
        },
    })


# ---------------------------------------------------------------------------
# Admin API (all require x-admin-token header == ADMIN_PANEL_TOKEN)
# ---------------------------------------------------------------------------

@app.route("/api/admin-settings", methods=["GET", "PUT", "OPTIONS"])
def admin_settings():
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if request.method == "GET":
        return json_response({"success": True, "settings": db_read()["site_settings"]})

    body = request.get_json(silent=True) or {}
    row = {
        "id": 1,
        "site_name": body.get("site_name"),
        "footer_name": body.get("footer_name"),
        "logo_url": body.get("logo_url"),
        "admin_telegram_link": body.get("admin_telegram_link"),
        "admin_telegram_name": body.get("admin_telegram_name"),
        "facebook_link": body.get("facebook_link"),
        "tiktok_link": body.get("tiktok_link"),
        "footer_desc": body.get("footer_desc"),
        "copyright": body.get("copyright"),
        "khqr_logo_url": body.get("khqr_logo_url"),
        "aba_logo_url": body.get("aba_logo_url"),
    }

    def _mutate(d):
        d["site_settings"] = row

    db_write(_mutate)
    return json_response({"success": True, "settings": row})


@app.route("/api/admin-test-notify", methods=["POST", "OPTIONS"])
def admin_test_notify():
    """Sends a real Telegram test message and reports the actual result back to the
    admin panel, instead of failing silently like notify_admin() does elsewhere.
    Use this to verify TELEGRAM_BOT_TOKEN / ADMIN_CHAT_ID are configured correctly
    without waiting for a real payment or new-user event."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if not TELEGRAM_BOT_TOKEN:
        return json_response({"success": False, "error": "TELEGRAM_BOT_TOKEN មិនទាន់បានកំណត់ក្នុង environment variables"}, 400)
    if not ADMIN_CHAT_ID:
        return json_response({"success": False, "error": "ADMIN_CHAT_ID មិនទាន់បានកំណត់ក្នុង environment variables"}, 400)

    try:
        res = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": ADMIN_CHAT_ID,
                "text": "✅ *TEST NOTIFICATION*\nប្រព័ន្ធ Telegram notification របស់ SANTA TOPUP ដំណើរការត្រឹមត្រូវ!",
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
        data = res.json()
    except requests.RequestException as e:
        return json_response({"success": False, "error": "Network error: " + str(e)}, 502)

    if not data.get("ok"):
        # Telegram's own error text - e.g. "Unauthorized" (bad token),
        # "chat not found" (bad ADMIN_CHAT_ID), or "bot was blocked by the user".
        return json_response({"success": False, "error": data.get("description", "Telegram API returned an unknown error")}, 400)

    return json_response({"success": True, "message": "សារបានផ្ញើដោយជោគជ័យ — ពិនិត្យ Telegram robot របស់អ្នក"})


@app.route("/api/admin-security-log", methods=["GET", "OPTIONS"])
def admin_security_log():
    """Live view of the in-memory rate-limit/ban store — who is currently
    banned or racking up strikes. This resets on every restart/redeploy (it's
    RAM, not a database), so it only shows activity since the last deploy,
    not historical attacks."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if not _HAS_LIMITER:
        return json_response({"success": True, "rows": [], "limiter_enabled": False})

    now = time.time()
    rows = []
    for ip, info in _ban_store.items():
        rows.append({
            "ip": ip,
            "strikes": info.get("strikes", 0),
            "banned_now": now < info.get("banned_until", 0),
            "banned_until": info.get("banned_until", 0),
            "banned_seconds_left": max(0, int(info.get("banned_until", 0) - now)),
            "last_violation": info.get("last", 0),
        })
    rows.sort(key=lambda r: r["last_violation"], reverse=True)
    return json_response({"success": True, "rows": rows, "limiter_enabled": True, "server_time": now})


NUMERIC_FIELDS = {"products": {"price", "cost_usd"}}


def _coerce_fields(table_name, row):
    for f in NUMERIC_FIELDS.get(table_name, ()):
        if row.get(f) not in (None, ""):
            try:
                row[f] = float(row[f])
            except (TypeError, ValueError):
                pass
    # Frontend only renders products whose "section" is exactly "recommend" or
    # "normal" (anything else, including missing/blank, is silently invisible).
    # Default every product to "normal" unless the admin explicitly picked "recommend".
    if table_name == "products":
        if row.get("section") not in ("recommend", "normal"):
            row["section"] = "normal"


def _admin_crud(table_name, allowed_fields, required_on_create):
    """Generic GET/POST/PUT/DELETE handler for games / products / banners."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if request.method == "GET":
        data = db_read()
        rows = data[table_name]
        game_code = request.args.get("game_code")
        if game_code and table_name == "products":
            rows = [r for r in rows if r.get("game_code") == game_code]
        return json_response({"success": True, table_name: rows})

    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        if any(body.get(f) in (None, "") for f in required_on_create):
            return json_response({"success": False, "error": f"Missing {', '.join(required_on_create)}"}, 400)

        def _mutate(d):
            row = {"id": next_id(d, table_name)}
            for f in allowed_fields:
                row[f] = body.get(f)
            _coerce_fields(table_name, row)
            d[table_name].append(row)
            return row

        row = db_write(_mutate)
        singular = table_name[:-1] if table_name != "banners" else "banner"
        return json_response({"success": True, singular: row})

    if request.method == "PUT":
        body = request.get_json(silent=True) or {}
        row_id = body.get("id")
        if not row_id:
            return json_response({"success": False, "error": "Missing id"}, 400)

        def _mutate(d):
            row = find_by_id(d[table_name], row_id)
            if row is None:
                return None
            for f in allowed_fields:
                if f in body:
                    row[f] = body.get(f)
            _coerce_fields(table_name, row)
            return row

        row = db_write(_mutate)
        if row is None:
            return json_response({"success": False, "error": "Not found"}, 404)
        singular = table_name[:-1] if table_name != "banners" else "banner"
        return json_response({"success": True, singular: row})

    if request.method == "DELETE":
        row_id = request.args.get("id")
        if not row_id:
            return json_response({"success": False, "error": "Missing id"}, 400)

        def _mutate(d):
            d[table_name] = [r for r in d[table_name] if str(r.get("id")) != str(row_id)]

        db_write(_mutate)
        return json_response({"success": True})

    return json_response({"success": False, "error": "Method not allowed"}, 405)


@app.route("/api/admin-games", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def admin_games():
    # khmertopup_slug: the Khmer TopUp game `slug` (enables auto ID-check + auto
    # top-up for this game). Get it from GET /api/admin-khmertopup-games.
    # has_server_id: set true whenever that game's `server_label` in the Khmer
    # TopUp catalogue is non-null (e.g. Mobile Legends' "Zone ID").
    return _admin_crud(
        "games",
        ["name", "code", "image_url", "khmertopup_slug", "has_server_id", "fulfillment_type"],
        required_on_create=["name", "code"],
    )


@app.route("/api/admin-products", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def admin_products():
    # provider_package holds the Khmer TopUp integer `package_id` for this product
    # (from GET /api/admin-khmertopup-games -> that game's `packages` list).
    # cost_usd is the Khmer TopUp reseller price for that package (fill in manually
    # from the same list) — used only to compute profit margin in the admin panel;
    # it is never shown to customers.
    return _admin_crud(
        "products",
        ["game_code", "name", "price", "cost_usd", "provider_package", "image_url", "section"],
        required_on_create=["game_code", "name"],
    )



# Bulk-import rule for "add all packages at once": only packages whose Khmer
# TopUp wholesale cost falls in this $3-$8 band get auto-imported, each priced
# with a random 5%-15% profit margin on top of cost. Packages outside the band
# are skipped (add them by hand from the Products tab if you want them) so a
# single click never silently mis-prices a $50 package at a few cents' margin.
BULK_IMPORT_COST_MIN = 3.0
BULK_IMPORT_COST_MAX = 8.0
BULK_IMPORT_MARGIN_MIN = 0.05
BULK_IMPORT_MARGIN_MAX = 0.15


@app.route("/api/admin-products-bulk-import", methods=["POST", "OPTIONS"])
def admin_products_bulk_import():
    """Add every package of one game as a product in a single call ("add all
    packages at once"). The client sends the raw Khmer TopUp package list
    (name/cost/package_id) for one game_code; price is never trusted from the
    client — it's always computed here as cost * (1 + random margin in
    [BULK_IMPORT_MARGIN_MIN, BULK_IMPORT_MARGIN_MAX]), and only for packages
    costing between BULK_IMPORT_COST_MIN and BULK_IMPORT_COST_MAX. Packages
    already imported (same game_code + provider_package) are skipped so this
    is safe to click again after Khmer TopUp adds new packages.
    """
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    body = request.get_json(silent=True) or {}
    game_code = body.get("game_code")
    items = body.get("items")
    if not game_code or not isinstance(items, list) or not items:
        return json_response({"success": False, "error": "Missing game_code or items"}, 400)

    def _mutate(d):
        existing_packages = {
            str(p.get("provider_package"))
            for p in d["products"]
            if p.get("game_code") == game_code and p.get("provider_package") not in (None, "")
        }
        added, skipped_duplicate, skipped_out_of_range, skipped_invalid = [], 0, 0, 0
        for item in items:
            pkg_id = item.get("provider_package")
            if pkg_id in (None, ""):
                skipped_invalid += 1
                continue
            if str(pkg_id) in existing_packages:
                skipped_duplicate += 1
                continue
            try:
                cost = float(item.get("cost_usd"))
            except (TypeError, ValueError):
                skipped_invalid += 1
                continue
            if not (BULK_IMPORT_COST_MIN <= cost <= BULK_IMPORT_COST_MAX):
                skipped_out_of_range += 1
                continue
            margin = random.uniform(BULK_IMPORT_MARGIN_MIN, BULK_IMPORT_MARGIN_MAX)
            price = round(cost * (1 + margin), 2)
            row = {
                "id": next_id(d, "products"),
                "game_code": game_code,
                "name": item.get("name") or "",
                "price": price,
                "cost_usd": cost,
                "provider_package": pkg_id,
                "image_url": item.get("image_url") or "",
                "section": "normal",
            }
            d["products"].append(row)
            existing_packages.add(str(pkg_id))
            added.append(row)
        return {
            "added": added,
            "added_count": len(added),
            "skipped_duplicate": skipped_duplicate,
            "skipped_out_of_range": skipped_out_of_range,
            "skipped_invalid": skipped_invalid,
        }

    result = db_write(_mutate)
    return json_response({"success": True, **result})


@app.route("/api/admin-khmertopup-games", methods=["GET", "OPTIONS"])
def admin_khmertopup_games():
    """Live remote catalogue — lets the admin panel populate a dropdown of Khmer
    TopUp slugs/package_ids instead of hand-typing them. force=1 bypasses the
    in-process cache (e.g. right after Khmer TopUp adds a new game)."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err
    try:
        data = khmertopup_get_games(force=request.args.get("force") == "1")
    except KhmerTopUpError as e:
        return json_response({"success": False, "error": str(e)}, 502)
    return json_response({"success": True, "games": data.get("games", [])})


@app.route("/api/admin-khmertopup-balance", methods=["GET", "OPTIONS"])
def admin_khmertopup_balance():
    """Live wallet balance — shown in the admin panel so you notice a low balance
    before orders start failing with 402 Insufficient wallet balance."""
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err
    try:
        data = khmertopup_get_balance()
    except KhmerTopUpError as e:
        return json_response({"success": False, "error": str(e)}, 502)
    return json_response({"success": True, **data})


@app.route("/api/admin-banners", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def admin_banners():
    # 'type' MUST be "main_slider" or "small_promo" — the frontend filters banners by
    # this field to decide where to render them (see u.banners.filter(S=>S.type===...)
    # in the site bundle). A banner with no/wrong type is silently invisible on the site.
    return _admin_crud("banners", ["image_url", "link", "type"], required_on_create=["image_url", "type"])


@app.route("/api/admin-transactions", methods=["GET", "PATCH", "OPTIONS"])
def admin_transactions():
    if request.method == "OPTIONS":
        return json_response({})
    auth_err = require_admin()
    if auth_err:
        return auth_err

    if request.method == "GET":
        status = request.args.get("status")
        limit = int(request.args.get("limit", 50))
        data = db_read()
        rows = data["transactions"]
        if status:
            rows = [r for r in rows if r.get("status") == status]
        rows = sorted(rows, key=lambda t: t.get("created_at") or "", reverse=True)[:limit]
        return json_response({"success": True, "transactions": rows})

    body = request.get_json(silent=True) or {}
    trx_id = body.get("trx_id")
    delivery_status = body.get("delivery_status")
    allowed = ["pending", "processing", "delivered", "failed", "manual"]
    if not trx_id or not delivery_status:
        return json_response({"success": False, "error": "Missing trx_id or delivery_status"}, 400)
    if delivery_status not in allowed:
        return json_response({"success": False, "error": f"delivery_status must be one of: {', '.join(allowed)}"}, 400)

    def _mutate(d):
        o = find_by_id(d["transactions"], trx_id, key="trx_id")
        if o is None:
            return None
        o["delivery_status"] = delivery_status
        o["delivery_error"] = body.get("delivery_error")
        return o

    row = db_write(_mutate)
    if row is None:
        return json_response({"success": False, "error": "Not found"}, 404)
    return json_response({"success": True, "transaction": row})


# ---------------------------------------------------------------------------
# CORS (kept permissive like the original functions, in case you split domains)
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, x-client-id, x-admin-token"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return resp


# ---------------------------------------------------------------------------
# Global error handlers
#
# Without these, an unhandled exception in any view (a bad Khmer TopUp
# response shape, a malformed request body, a JSON decode error, etc.) can
# either leak an internal stack trace to the client or, under some gunicorn
# worker classes, take the worker down entirely. One bad/malicious request
# should never be able to degrade service for everyone else.
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def _handle_payload_too_large(e):
    return json_response({"success": False, "error": "Payload too large"}, 413)


@app.errorhandler(429)
def _handle_rate_limited(e):
    _register_violation(_client_ip())
    return json_response({"success": False, "error": "Too many requests — please slow down"}, 429)


@app.errorhandler(404)
def _handle_not_found(e):
    return json_response({"success": False, "error": "Not found"}, 404)


@app.errorhandler(Exception)
def _handle_unexpected_error(e):
    import traceback
    print("UNHANDLED ERROR:", traceback.format_exc())
    return json_response({"success": False, "error": "Internal server error"}, 500)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"SANTA TOPUP server running on http://0.0.0.0:{port}")
    print(f"  Site : http://localhost:{port}/")
    print(f"  Admin: http://localhost:{port}/admin (token = ADMIN_PANEL_TOKEN)")
    app.run(host="0.0.0.0", port=port, debug=False)
