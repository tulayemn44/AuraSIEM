#!/usr/bin/env python3
"""
╔═══════════════════════════════════════╗
║           ✦ AuraSIEM ✦                ║
║   Your personal threat detection      ║
║   engine — pink, pretty, powerful.    ║
╚═══════════════════════════════════════╝

Setup:   pip install flask requests python-dotenv
Run:     python3 aura_siem_github.py
Phone:   open http://<your-mac-ip>:8080
"""

import os
import random
import re
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime

import requests
from flask import Flask, jsonify
from dotenv import load_dotenv

# .env dosyasındaki gizli değişkenleri yükler
load_dotenv()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  YOUR SETTINGS — SECURED VIA .ENV
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Token ve Chat ID kodun içinden tamamen temizlendi, .env dosyasından okunuyor.
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# How many failed logins from one IP triggers a brute-force alert?
BRUTE_FORCE_LIMIT = 4

# How often new fake logs are generated (seconds)
LOG_INTERVAL = 4

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  FAKE LOG GENERATOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ATTACKER_IPS = [
    "185.220.101.47", "45.33.32.156", "192.241.229.6",
    "104.21.44.18",   "23.129.64.131", "66.240.205.34",
]
SAFE_IPS = [
    "10.0.0.2", "10.0.0.5", "192.168.1.10", "192.168.1.42",
]
USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "git"]
HTTP_PATHS = [
    "/login", "/admin", "/wp-login.php", "/.env",
    "/api/users", "/dashboard", "/../../../etc/passwd",
    "/shell.php", "/config.php",
]

LOG_TEMPLATES = [
    # SSH failures (high threat)
    ("ssh_fail",
     lambda: f"{_ts()} server sshd[{_pid()}]: Failed password for {random.choice(USERNAMES)} "
             f"from {random.choice(ATTACKER_IPS)} port {random.randint(40000,65000)} ssh2"),

    # SSH success (benign)
    ("ssh_ok",
     lambda: f"{_ts()} server sshd[{_pid()}]: Accepted password for deploy "
             f"from {random.choice(SAFE_IPS)} port 22 ssh2"),

    # HTTP suspicious
    ("http_suspicious",
     lambda: f"{_ts()} server nginx: {random.choice(ATTACKER_IPS)} - - "
             f"\"GET {random.choice(HTTP_PATHS)} HTTP/1.1\" "
             f"{random.choice([400,403,404,500])} -"),

    # Port scan
    ("port_scan",
     lambda: f"{_ts()} server kernel: DROP IN=eth0 SRC={random.choice(ATTACKER_IPS)} "
             f"DPT={random.randint(1,9999)} PROTO=TCP FLAGS=SYN"),

    # Normal system noise
    ("system",
     lambda: f"{_ts()} server systemd[1]: {random.choice(['Started', 'Stopped', 'Reloaded'])} "
             f"{random.choice(['nginx.service', 'cron.service', 'sshd.service'])}"),
]

# Weighted so attacks appear realistically — not every line is a threat
LOG_WEIGHTS = [35, 10, 20, 10, 25]

def _ts():
    return datetime.now().strftime("%b %d %H:%M:%S")

def _pid():
    return random.randint(1000, 9999)

def generate_log():
    template_type, fn = random.choices(LOG_TEMPLATES, weights=LOG_WEIGHTS, k=1)[0]
    return template_type, fn()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  DETECTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PATTERNS = [
    {
        "id":       "failed_login",
        "label":    "Failed Login",
        "severity": "high",
        "regex":    re.compile(r"Failed password|Invalid user|authentication failure", re.I),
    },
    {
        "id":       "success_login",
        "label":    "Successful Login",
        "severity": "low",
        "regex":    re.compile(r"Accepted password|session opened", re.I),
    },
    {
        "id":       "port_scan",
        "label":    "Port Scan",
        "severity": "high",
        "regex":    re.compile(r"DPT=\d+.*PROTO=TCP|port scan|nmap", re.I),
    },
    {
        "id":       "web_attack",
        "label":    "Web Attack",
        "severity": "medium",
        "regex":    re.compile(r"(etc/passwd|\.env|wp-login|shell\.php|\.\.\/)", re.I),
    },
    {
        "id":       "error",
        "label":    "System Error",
        "severity": "low",
        "regex":    re.compile(r"\b(error|fatal|critical|panic)\b", re.I),
    },
]

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def detect(line: str) -> dict:
    """Parse one log line and return an event dict."""
    ip_match = IP_RE.search(line)
    ip = ip_match.group(1) if ip_match else None

    for p in PATTERNS:
        if p["regex"].search(line):
            return {
                "id":       p["id"],
                "label":    p["label"],
                "severity": p["severity"],
                "ip":       ip,
                "raw":      line.strip()[:280],
                "time":     datetime.now().strftime("%H:%M:%S"),
                "ts":       time.time(),
            }

    return {
        "id":       "info",
        "label":    "Info",
        "severity": "none",
        "ip":       ip,
        "raw":      line.strip()[:280],
        "time":     datetime.now().strftime("%H:%M:%S"),
        "ts":       time.time(),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  STATE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

events     = []  # last 300 events
ip_hits    = defaultdict(int)
alerted    = set()       # IPs we already alerted on
stats      = {"total": 0, "high": 0, "medium": 0, "low": 0}
start_time = datetime.now()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  TELEGRAM
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def send_alert(message: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[Telegram not configured] Please check your .env file.")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        response = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=5,
        )
        if response.status_code != 200:
            print(f"[Telegram Sunucu Hatası] Kod: {response.status_code}")
    except Exception as e:
        print(f"[Telegram error] {e}")


def maybe_alert(event: dict):
    ip = event.get("ip")

    # Brute force: same IP, too many failed logins
    if event["id"] == "failed_login" and ip:
        ip_hits[ip] += 1
        if ip_hits[ip] == BRUTE_FORCE_LIMIT and ip not in alerted:
            alerted.add(ip)
            send_alert(
                f"🚨 <b>AuraSIEM — Brute Force Detected</b>\n\n"
                f"🌸 IP: <code>{ip}</code>\n"
                f"💥 Attempts: {ip_hits[ip]}\n"
                f"⏰ Time: {event['time']}"
            )

    # Port scan alert (always)
    if event["id"] == "port_scan" and ip and ip not in alerted:
        alerted.add(ip)
        send_alert(
            f"🔍 <b>AuraSIEM — Port Scan Detected</b>\n\n"
            f"🌸 IP: <code>{ip}</code>\n"
            f"⏰ Time: {event['time']}"
        )

    # Web attack alert
    if event["id"] == "web_attack":
        send_alert(
            f"🕸️ <b>AuraSIEM — Web Attack</b>\n\n"
            f"🌸 IP: <code>{ip or 'unknown'}</code>\n"
            f"📝 {event['raw'][:120]}\n"
            f"⏰ {event['time']}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  ENGINE LOOP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def engine_loop():
    global events, stats
    while True:
        _, raw_line = generate_log()
        event = detect(raw_line)

        events = ([event] + events)[:300]

        stats["total"] += 1
        if event["severity"] == "high":
            stats["high"] += 1
        elif event["severity"] == "medium":
            stats["medium"] += 1
        elif event["severity"] == "low":
            stats["low"] += 1

        maybe_alert(event)
        time.sleep(LOG_INTERVAL)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  DASHBOARD HTML
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>✦ AuraSIEM</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

:root {
  --bg:       #0e0910;
  --surface:  #17101f;
  --surface2: #201629;
  --border:   rgba(220,180,255,0.1);
  --pink:     #f472b6;
  --purple:   #c084fc;
  --lavender: #a78bfa;
  --soft:     #e879f9;
  --text:     #f0e6ff;
  --muted:    #9d7eb8;
  --high:     #fb7185;
  --medium:   #fbbf24;
  --low:      #a78bfa;
  --none:     #4a3d5c;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}

.header {
  background: linear-gradient(135deg, #1a0b2e, #2d1054);
  border-bottom: 1px solid var(--border);
  padding: 18px 16px 14px;
  position: sticky; top: 0; z-index: 20;
}
.header-top {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 4px;
}
.logo {
  font-size: 18px; font-weight: 600;
  background: linear-gradient(90deg, var(--pink), var(--purple));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  letter-spacing: -0.3px;
}
.live-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: #4ade80;
  animation: pulse 2s infinite;
  display: inline-block; margin-right: 6px;
}
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
.uptime { font-size: 11px; color: var(--muted); }
.last-update { font-size: 11px; color: var(--muted); }

.stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px; padding: 14px 12px 10px;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px; padding: 12px 8px;
  text-align: center;
}
.stat-val {
  font-size: 22px; font-weight: 600; line-height: 1;
  margin-bottom: 5px;
}
.stat-label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.c-pink    { color: var(--pink); }
.c-high    { color: var(--high); }
.c-medium  { color: var(--medium); }
.c-purple  { color: var(--purple); }

.section { padding: 0 12px 12px; }
.section-title {
  font-size: 11px; font-weight: 600;
  color: var(--muted); text-transform: uppercase;
  letter-spacing: .08em; margin-bottom: 8px;
}
.ip-list { display: flex; flex-direction: column; gap: 6px; }
.ip-row {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 12px;
  display: flex; align-items: center; gap: 10px;
}
.ip-addr { font-family: monospace; font-size: 13px; flex: 1; }
.ip-count {
  font-size: 12px; font-weight: 600;
  background: rgba(244,114,182,.15);
  color: var(--pink);
  padding: 2px 8px; border-radius: 20px;
}
.bar-wrap { width: 60px; height: 4px; background: var(--border); border-radius: 2px; }
.bar-fill { height: 100%; border-radius: 2px; background: linear-gradient(90deg, var(--pink), var(--purple)); }

.filters {
  display: flex; gap: 6px;
  padding: 0 12px 10px;
  overflow-x: auto; scrollbar-width: none;
}
.filters::-webkit-scrollbar { display: none; }
.pill {
  border: 1px solid var(--border);
  background: transparent;
  color: var(--muted);
  padding: 5px 14px; border-radius: 20px;
  font-size: 12px; white-space: nowrap; cursor: pointer;
  font-family: 'Inter', sans-serif;
  transition: all .15s;
}
.pill.active {
  background: rgba(196,132,252,.15);
  border-color: var(--purple);
  color: var(--purple);
}

.feed { padding: 0 12px 90px; display: flex; flex-direction: column; gap: 6px; }

.event {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--none);
  border-radius: 0 10px 10px 0;
  padding: 10px 12px;
  animation: fadein .3s ease;
}
@keyframes fadein { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }

.event[data-sev="high"]   { border-left-color: var(--high); }
.event[data-sev="medium"] { border-left-color: var(--medium); }
.event[data-sev="low"]    { border-left-color: var(--low); }

.event-top { display: flex; align-items: center; gap: 6px; margin-bottom: 5px; flex-wrap: wrap; }

.badge {
  font-size: 10px; font-weight: 600;
  padding: 2px 7px; border-radius: 4px;
  text-transform: uppercase; letter-spacing: .04em;
}
.badge-high   { background: rgba(251,113,133,.15); color: var(--high); }
.badge-medium { background: rgba(251,191,36,.12);  color: var(--medium); }
.badge-low    { background: rgba(167,139,250,.15); color: var(--low); }
.badge-none   { background: rgba(74,61,92,.4);     color: var(--muted); }

.event-ip {
  font-size: 10px; font-family: monospace;
  background: rgba(220,180,255,.07);
  color: var(--lavender);
  padding: 1px 6px; border-radius: 4px;
}
.event-time { font-size: 10px; color: var(--muted); margin-left: auto; }
.event-raw  {
  font-family: monospace; font-size: 11px;
  color: var(--muted); line-height: 1.5; word-break: break-all;
}

.fab {
  position: fixed; bottom: 22px; right: 18px;
  width: 50px; height: 50px; border-radius: 50%;
  background: linear-gradient(135deg, var(--pink), var(--purple));
  border: none; color: white; font-size: 20px;
  cursor: pointer; box-shadow: 0 4px 20px rgba(196,132,252,.35);
  display: flex; align-items: center; justify-content: center;
}

.empty { text-align: center; color: var(--muted); padding: 2rem; font-size: 14px; }
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">✦ AuraSIEM</div>
    <div><span class="live-dot"></span><span style="font-size:11px;color:#4ade80">live</span></div>
  </div>
  <div style="display:flex;justify-content:space-between">
    <span class="uptime" id="uptime">starting...</span>
    <span class="last-update" id="last-update">–</span>
  </div>
</div>

<div class="stats" id="stats"></div>

<div class="section">
  <div class="section-title">🎯 Top attacker IPs</div>
  <div class="ip-list" id="ip-list"></div>
</div>

<div class="filters">
  <button class="pill active" onclick="filter('all',this)">All</button>
  <button class="pill" onclick="filter('failed_login',this)">Failed Login</button>
  <button class="pill" onclick="filter('port_scan',this)">Port Scan</button>
  <button class="pill" onclick="filter('web_attack',this)">Web Attack</button>
  <button class="pill" onclick="filter('success_login',this)">Success</button>
  <button class="pill" onclick="filter('info',this)">Info</button>
</div>

<div class="feed" id="feed"></div>

<button class="fab" onclick="load()" title="Refresh">↻</button>

<script>
let allEvents = [];
let currentFilter = 'all';

function filter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  render();
}

function render() {
  const shown = currentFilter === 'all'
    ? allEvents
    : allEvents.filter(e => e.id === currentFilter);

  const feed = document.getElementById('feed');
  if (!shown.length) {
    feed.innerHTML = '<div class="empty">No events yet 🌸</div>';
    return;
  }

  feed.innerHTML = shown.slice(0, 60).map(e => `
    <div class="event" data-sev="${e.severity}">
      <div class="event-top">
        <span class="badge badge-${e.severity}">${e.label}</span>
        ${e.ip ? `<span class="event-ip">${e.ip}</span>` : ''}
        <span class="event-time">${e.time}</span>
      </div>
      <div class="event-raw">${e.raw.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
    </div>`).join('');
}

function load() {
  fetch('/api/data').then(r => r.json()).then(d => {
    allEvents = d.events;

    const s = d.stats;
    document.getElementById('stats').innerHTML = `
      <div class="stat"><div class="stat-val c-pink">${s.total}</div><div class="stat-label">Total</div></div>
      <div class="stat"><div class="stat-val c-high">${s.high}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-val c-medium">${s.medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-val c-purple">${s.low}</div><div class="stat-label">Low</div></div>`;

    const ips = d.top_ips;
    const maxHits = ips.length ? ips[0][1] : 1;
    document.getElementById('ip-list').innerHTML = ips.length
      ? ips.map(([ip, count]) => `
          <div class="ip-row">
            <span class="ip-addr">${ip}</span>
            <div class="bar-wrap"><div class="bar-fill" style="width:${Math.round(count/maxHits*100)}%"></div></div>
            <span class="ip-count">${count}</span>
          </div>`).join('')
      : '<div class="empty">No suspicious IPs yet 🌸</div>';

    document.getElementById('uptime').textContent = 'uptime ' + d.uptime;
    document.getElementById('last-update').textContent = 'updated ' + new Date().toLocaleTimeString();

    render();
  });
}

load();
setInterval(load, 5000);
</script>
</body>
</html>"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  FLASK ROUTES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app = Flask(__name__)

@app.route("/")
def index():
    return DASHBOARD

@app.route("/api/data")
def api_data():
    top_ips = sorted(ip_hits.items(), key=lambda x: x[1], reverse=True)[:5]
    delta = datetime.now() - start_time
    hours, rem = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(rem, 60)
    uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    return jsonify({
        "events":  events,
        "stats":   stats,
        "top_ips": top_ips,
        "uptime":  uptime,
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ✦  LAUNCH
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    print()
    print("  ✦  AuraSIEM (GitHub Version) is waking up...  ✦")
    print()

    telegram_ok = len(TELEGRAM_TOKEN) > 0 and len(TELEGRAM_CHAT_ID) > 0
    print(f"  Telegram alerts : {'✓ configured via .env' if telegram_ok else '✗ pending .env setup'}")
    print(f"  Log interval    : every {LOG_INTERVAL}s")
    print(f"  Brute-force lim : {BRUTE_FORCE_LIMIT} attempts")
    print()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "localhost"

    print(f"  Open on your browser:")
    print(f"  ➜  http://{local_ip}:8080")
    print()

    thread = threading.Thread(target=engine_loop, daemon=True)
    thread.start()

    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
