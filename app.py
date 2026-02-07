import os
import hmac
import hashlib
import time
import json
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

# ====== CONFIG (set these on Render as Environment Variables) ======
BOT_TOKEN = "8295237011:AAHBrRTXCeK4Qp1WGYrQml1eorL3Loki58A"
BOT_USERNAME = "@gggggmailllll_bot"
API_SECRET = A1_VERIFY_20H_RS_8958965386

# In-memory store (simple). For production: use DB (Postgres/SQLite)
VERIFIED: Dict[int, Dict[str, Any]] = {}  # user_id -> data


# ---------- Telegram WebApp initData verification ----------
def parse_init_data(init_data: str) -> Dict[str, str]:
    # initData is querystring like: "query_id=...&user=...&auth_date=...&hash=..."
    out = {}
    for part in init_data.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def check_init_data(init_data: str, bot_token: str) -> bool:
    """
    Verify Telegram WebApp initData signature.
    Ref: Telegram Web Apps auth flow (HMAC-SHA256).
    """
    if not bot_token:
        return False

    data = parse_init_data(init_data)
    received_hash = data.get("hash", "")
    if not received_hash:
        return False

    # Build data_check_string from all fields except hash
    pairs = []
    for k in sorted(data.keys()):
        if k == "hash":
            continue
        pairs.append(f"{k}={data[k]}")
    data_check_string = "\n".join(pairs)

    secret_key = hmac.new(
        key=b"WebAppData",
        msg=bot_token.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()

    calculated_hash = hmac.new(
        key=secret_key,
        msg=data_check_string.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(calculated_hash, received_hash)


def get_client_ip(request: Request) -> str:
    # Render / proxies may pass forwarded headers
    hdr = request.headers
    # Cloudflare / proxies:
    ip = hdr.get("cf-connecting-ip") or hdr.get("x-forwarded-for") or ""
    if ip:
        # x-forwarded-for can be "client, proxy1, proxy2"
        return ip.split(",")[0].strip()
    # fallback
    client = request.client.host if request.client else ""
    return client or ""


# ---------- UI (matches your screenshot concept) ----------
HTML_PAGE = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Device Verification</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    :root{
      --bg1:#070a1a; --bg2:#0b1b52;
      --card:rgba(30, 40, 90, 0.35);
      --border:rgba(255,255,255,0.08);
      --btn1:#7a5cff; --btn2:#4fd1c5;
      --text:#e9ecff; --muted:rgba(233,236,255,0.7);
    }
    body{
      margin:0; min-height:100vh;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color:var(--text);
      background: radial-gradient(1200px 800px at 50% 30%, var(--bg2), var(--bg1));
      display:flex; align-items:center; justify-content:center;
      padding:24px;
      overflow:hidden;
    }
    .stars{position:fixed; inset:0; opacity:.35; pointer-events:none; background:
      radial-gradient(circle at 20% 30%, #ffffff 1px, transparent 2px) 0 0/140px 140px,
      radial-gradient(circle at 60% 70%, #ffffff 1px, transparent 2px) 0 0/190px 190px,
      radial-gradient(circle at 80% 20%, #ffffff 1px, transparent 2px) 0 0/220px 220px;
      filter: blur(.2px);
    }
    .card{
      width:min(420px, 94vw);
      background:var(--card);
      border:1px solid var(--border);
      border-radius:24px;
      backdrop-filter: blur(14px);
      box-shadow: 0 20px 80px rgba(0,0,0,0.45);
      padding:28px 22px;
      text-align:center;
    }
    .icon{
      width:92px; height:92px;
      margin:0 auto 12px;
      border-radius:999px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(122,92,255,0.20);
      border:1px solid rgba(122,92,255,0.25);
      box-shadow: 0 0 0 10px rgba(122,92,255,0.06);
      font-size:42px;
    }
    h1{margin:10px 0 6px; font-size:30px; letter-spacing:.2px;}
    p{margin:0 0 16px; color:var(--muted); line-height:1.5;}
    .btn{
      width:100%;
      border:0;
      border-radius:16px;
      padding:14px 16px;
      font-size:16px;
      font-weight:700;
      color:white;
      background: linear-gradient(90deg, var(--btn1), var(--btn2));
      cursor:pointer;
    }
    .mini{
      margin-top:12px;
      font-size:12px;
      color:rgba(233,236,255,0.6);
      white-space:pre-wrap;
      text-align:left;
      display:none;
    }
  </style>
</head>
<body>
  <div class="stars"></div>
  <div class="card">
    <div class="icon">👤✅</div>
    <h1 id="title">Checking...</h1>
    <p id="sub">Please wait...</p>

    <button class="btn" id="btn" style="display:none;">🤖 Proceed to Bot</button>

    <div class="mini" id="debug"></div>
  </div>

<script>
  const tg = window.Telegram.WebApp;
  tg.ready();

  const title = document.getElementById('title');
  const sub = document.getElementById('sub');
  const btn = document.getElementById('btn');
  const debug = document.getElementById('debug');

  function getSignals() {
    const ua = navigator.userAgent || "";
    const tz = Intl?.DateTimeFormat?.().resolvedOptions?.().timeZone || "";
    const screenSize = (screen.width + "x" + screen.height);
    const lang = (navigator.language || "");
    return { ua, tz, screen: screenSize, lang };
  }

  async function postVerify() {
    try {
      const initData = tg.initData || "";
      const u = tg.initDataUnsafe?.user || null;

      if (!u || !initData) {
        title.textContent = "Verification Error";
        sub.textContent = "Open this page only from the Telegram bot button.";
        return;
      }

      const payload = {
        init_data: initData,
        user: u,
        signals: getSignals(),
        ts: Date.now()
      };

      const r = await fetch("/api/webapp/verify", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(payload)
      });

      const j = await r.json();

      if (!r.ok || !j.ok) {
        title.textContent = "Verification Failed";
        sub.textContent = j.error || ("Server error " + r.status);
        return;
      }

      if (j.already_verified) {
        title.textContent = "Already Verified";
        sub.textContent = "This account is already verified.";
      } else {
        title.textContent = "Verified";
        sub.textContent = "Your device has been verified successfully.";
      }

      btn.style.display = "block";
      btn.onclick = () => {
        // Close WebApp (returns to bot)
        tg.close();
      };

      // Optional debug (hidden)
      // debug.style.display = "block";
      // debug.textContent = JSON.stringify(j, null, 2);

    } catch (e) {
      title.textContent = "Verification Error";
      sub.textContent = String(e);
    }
  }

  postVerify();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_PAGE


@app.post("/api/webapp/verify")
async def webapp_verify(request: Request):
    try:
        body = await request.json()
        init_data = (body.get("init_data") or "").strip()
        user = body.get("user") or {}
        signals = body.get("signals") or {}

        if not init_data:
            return JSONResponse({"ok": False, "error": "Missing init_data"}, status_code=400)
        if not check_init_data(init_data, BOT_TOKEN):
            return JSONResponse({"ok": False, "error": "Invalid initData signature"}, status_code=403)

        user_id = int(user.get("id"))
        username = user.get("username") or ""
        name = (user.get("first_name") or "") + (" " + user.get("last_name") if user.get("last_name") else "")
        platform = (body.get("platform") or "")  # optional; Telegram doesn't always provide here
        is_premium = bool(user.get("is_premium", False))

        ip = get_client_ip(request)
        now = int(time.time())

        already = user_id in VERIFIED

        VERIFIED[user_id] = {
            "user_id": user_id,
            "username": username,
            "name": name.strip(),
            "is_premium": is_premium,
            "ip": ip,
            "ua": (signals.get("ua") or "")[:300],
            "tz": (signals.get("tz") or "")[:64],
            "screen": (signals.get("screen") or "")[:32],
            "lang": (signals.get("lang") or "")[:32],
            "verified_at": now,
            "init_ok": True,
        }

        return {"ok": True, "already_verified": already, "user_id": user_id}
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"{type(e).__name__}: {e}"}, status_code=500)


# Bot can query verification status (protect with API_SECRET)
@app.get("/api/status")
async def status(user_id: int, secret: str):
    if secret != API_SECRET:
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=403)
    v = VERIFIED.get(int(user_id))
    return {"ok": True, "verified": bool(v), "data": v or {}}
