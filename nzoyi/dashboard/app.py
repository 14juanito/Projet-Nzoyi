"""
NZOYI — Console C2 Streamlit (standalone).

Esthetique "cyber ops console" : fond noir, neon vert, monospace, panneaux a
coins en crochets, matrix rain + scanlines CRT. Deux pages :
  Page 1 · Mission Control  — configuration + lancement
  Page 2 · Live Ops         — execution temps reel (simulation dry-run)

Lancement :
  python3 nzoyi/dashboard/app.py          # auto (venv + streamlit)
  streamlit run nzoyi/dashboard/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Permet `python3 app.py` : relance via streamlit + venv du projet.
if __name__ == "__main__" and "streamlit" not in sys.modules:
    import subprocess

    _root = Path(__file__).resolve().parents[2]
    _venv_py = _root / "venv" / "bin" / "python"
    _python = str(_venv_py) if _venv_py.is_file() else sys.executable
    raise SystemExit(
        subprocess.call(
            [_python, "-m", "streamlit", "run", str(Path(__file__).resolve()), *sys.argv[1:]]
        )
    )

import json
import os
import random
import time
from datetime import datetime

import streamlit as st


def _inject_html(html: str, height: int = 0) -> None:
    """Injecte du HTML/JS dans un iframe (execute les <script>).

    ``st.markdown`` retire les ``<script>`` ; on passe donc par un iframe.
    Utilise ``st.iframe`` (API courante) avec repli sur ``components.html``
    pour les versions plus anciennes de Streamlit.
    """
    try:
        st.iframe(html, height=height or 1)
    except (AttributeError, TypeError):  # pragma: no cover - anciennes versions
        import streamlit.components.v1 as components

        components.html(html, height=height)

# Import robuste du helper d'icones (exécution standalone ou en package).
try:
    from nzoyi.dashboard.icons import icon
except ModuleNotFoundError:  # pragma: no cover - lancement direct sans package
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from nzoyi.dashboard.icons import icon

# ── Optional plotly (fallback to st.line_chart) ──────────────────────────────
try:
    import plotly.graph_objects as go

    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

VERSION = "0.1.0"

# ── Palette "cyber ops console" ──────────────────────────────────────────────
BG = "#050a08"        # fond global
BG2 = "#0a120d"       # fond panneaux
NEON = "#00ff7f"      # neon principal
NEON_DIM = "#14c96a"  # neon attenue (bordures, accents secondaires)
ALERT = "#ff2e4d"     # rouge alerte
AMBER = "#e8a33d"     # ambre (avertissements)
TXT = "#a8c0b0"       # texte
TXT_DIM = "#5f7a6a"   # texte attenue

# Alias retro-compatibles avec l'ancien code de rendu (recolores).
GOLD = NEON
GREEN = NEON
RED = ALERT
CYAN = NEON_DIM
PURPLE = NEON_DIM
ORANGE = AMBER

# ── Predefined evasion strategies ────────────────────────────────────────────
STRATEGIES: dict[str, dict[str, float]] = {
    "ghost":         {"rate": 0.3, "pkt": 80,   "frag": 4, "jitter": 2.0, "ttl": 52},
    "ultra_stealth": {"rate": 0.5, "pkt": 64,   "frag": 3, "jitter": 1.5, "ttl": 58},
    "slow_frag":     {"rate": 1.0, "pkt": 128,  "frag": 2, "jitter": 0.8, "ttl": 64},
    "adaptive_v1":   {"rate": 1.5, "pkt": 192,  "frag": 2, "jitter": 1.0, "ttl": 60},
    "adaptive_v2":   {"rate": 0.8, "pkt": 96,   "frag": 3, "jitter": 1.2, "ttl": 55},
    "balanced":      {"rate": 5.0, "pkt": 512,  "frag": 0, "jitter": 0.2, "ttl": 128},
    "fast":          {"rate": 10.0, "pkt": 1024, "frag": 0, "jitter": 0.0, "ttl": 128},
}

AGENTS = ["recon", "enumerator", "vulnerability", "evasion", "attack", "evaluation"]
# Mappe chaque agent a une icone Lucide (remplace les anciens emojis).
AGENT_ICONS = {
    "recon": "search",
    "enumerator": "list",
    "vulnerability": "activity",
    "evasion": "eye-off",
    "attack": "crosshair",
    "evaluation": "shield",
}

# UNSW-NB15 features shown in the IDS panel and their "alert" thresholds.
FEATURE_THRESHOLDS = {"sttl": 80, "rate": 5, "dload": 5000, "dmean": 300}


# ═══════════════════════════════════════════════════════════════════════════
# CSS / THEME
# ═══════════════════════════════════════════════════════════════════════════
def inject_css() -> None:
    """Injecte le design system : fond transparent, panneaux, scanlines CRT."""
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

        html, body, [class*="css"], .stApp, .stMarkdown, input, textarea, button, select {{
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
        }}
        body {{ background: {BG}; }}
        /* Fond transparent pour laisser voir le canvas matrix rain. */
        .stApp,
        [data-testid="stAppViewContainer"],
        [data-testid="stHeader"] {{ background: transparent !important; }}
        [data-testid="stSidebar"] {{
            background: rgba(10,18,13,.88) !important;
            border-right: 1px solid rgba(20,201,106,.4);
        }}
        [data-testid="stAppViewContainer"] {{ color: {TXT}; }}

        /* Overlay scanlines CRT permanent + leger flicker. */
        .stApp::before {{
            content: ""; position: fixed; inset: 0; z-index: 3; pointer-events: none;
            background: repeating-linear-gradient(
                0deg, rgba(0,0,0,0) 0px, rgba(0,0,0,0) 2px,
                rgba(0,25,12,.22) 3px, rgba(0,0,0,0) 4px);
            animation: nz-flicker 4s infinite;
        }}
        @keyframes nz-flicker {{ 0%,100%{{opacity:.5}} 47%{{opacity:.55}} 50%{{opacity:.38}} 53%{{opacity:.55}} }}

        /* Panneaux a bordure neon + coins en crochets. */
        .nz-card {{
            position: relative; background: rgba(10,18,13,.72);
            border: 1px solid {NEON_DIM}; padding: 15px 16px 13px;
            margin-bottom: 14px; box-shadow: 0 0 12px rgba(0,255,127,.15);
        }}
        .nz-card::before, .nz-card::after {{
            content: ""; position: absolute; width: 12px; height: 12px;
        }}
        .nz-card::before {{ top:-1px; left:-1px;
            border-top: 2px solid {NEON}; border-left: 2px solid {NEON}; }}
        .nz-card::after {{ bottom:-1px; right:-1px;
            border-bottom: 2px solid {NEON}; border-right: 2px solid {NEON}; }}
        .nz-card-green {{ border-color: {NEON};
            box-shadow: 0 0 18px rgba(0,255,127,.25); }}
        .nz-card-red {{ border-color: {ALERT};
            box-shadow: 0 0 18px rgba(255,46,77,.22); }}
        .nz-card-red::before, .nz-card-red::after {{ border-color: {ALERT}; }}
        .nz-card-amber {{ border-color: {AMBER}; }}
        .nz-card-amber::before, .nz-card-amber::after {{ border-color: {AMBER}; }}

        .nz-title {{
            color: {NEON}; font-weight: 700; font-size: .78rem;
            letter-spacing: 2px; text-transform: uppercase; margin-bottom: 9px;
            display: flex; align-items: center; gap: 7px;
        }}
        .nz-title::before {{ content: "\\250C\\2500"; color: {NEON_DIM}; }}

        /* Barre de statut facon dashboard de hacking. */
        .nz-statusbar {{
            display: flex; flex-wrap: wrap; gap: 16px; align-items: center;
            background: rgba(10,18,13,.85); border: 1px solid {NEON_DIM};
            padding: 8px 16px; margin-bottom: 16px; font-size: .74rem;
            letter-spacing: 1px; color: {TXT_DIM}; text-transform: uppercase;
        }}
        .nz-statusbar b {{ color: {NEON}; }}
        .nz-statusbar .sep {{ color: {NEON_DIM}; opacity: .6; }}

        .dot {{ height:10px; width:10px; border-radius:50%; display:inline-block; margin-right:7px; }}
        .dot-run {{ background:{NEON}; box-shadow:0 0 10px {NEON}; animation: nz-pulse 1.1s infinite; }}
        .dot-idle {{ background:{ALERT}; box-shadow:0 0 8px {ALERT}; }}
        @keyframes nz-pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.35}} }}

        .badge {{ display:inline-block; padding:2px 9px; font-size:.68rem;
            font-weight:700; letter-spacing:1px; border:1px solid transparent; }}
        .b-pending {{ background:rgba(95,122,106,.15); color:{TXT_DIM}; border-color:{TXT_DIM}; }}
        .b-run {{ background:rgba(232,163,61,.15); color:{AMBER}; border-color:{AMBER}; }}
        .b-done {{ background:rgba(0,255,127,.12); color:{NEON}; border-color:{NEON}; }}
        .b-err {{ background:rgba(255,46,77,.15); color:{ALERT}; border-color:{ALERT}; }}

        .bar-wrap {{ background:rgba(20,201,106,.1); height:8px; width:100%;
            overflow:hidden; margin:3px 0 8px 0; border:1px solid rgba(20,201,106,.2); }}
        .bar-fill {{ height:100%; }}

        .term {{ background:rgba(1,6,4,.9); border:1px solid rgba(20,201,106,.35);
            padding:10px 12px; font-size:11px; line-height:1.55; height:340px;
            overflow-y:auto; white-space:pre-wrap; }}
        .term::-webkit-scrollbar {{ width:6px; }}
        .term::-webkit-scrollbar-thumb {{ background:{NEON_DIM}; }}
        .term .cur {{ color:{NEON}; animation: nz-blink 1s step-end infinite; }}
        @keyframes nz-blink {{ 50%{{opacity:0}} }}

        .reward {{ padding:8px; text-align:center; font-weight:700;
            letter-spacing:1px; margin:6px 0; border:1px solid transparent; }}
        .reward-ok {{ background:rgba(0,255,127,.12); color:{NEON};
            border-color:{NEON}; text-shadow:0 0 8px {NEON}; }}
        .reward-bad {{ background:rgba(255,46,77,.12); color:{ALERT};
            border-color:{ALERT}; text-shadow:0 0 8px {ALERT}; }}

        .recap {{ font-size:.82rem; background:rgba(10,18,13,.72);
            border:1px solid {NEON_DIM}; padding:12px; }}
        .recap div {{ display:flex; justify-content:space-between; padding:3px 0;
            border-bottom:1px dashed rgba(20,201,106,.18); }}
        .recap b {{ color:{NEON}; }}

        /* Boutons style terminal. */
        .stButton > button, .stDownloadButton > button {{
            background: transparent !important; color: {NEON} !important;
            border: 1px solid {NEON_DIM} !important; border-radius: 0 !important;
            text-transform: uppercase; letter-spacing: 2px; font-weight: 700 !important;
            transition: all .15s ease;
        }}
        .stButton > button:hover, .stDownloadButton > button:hover {{
            background: {NEON} !important; color: {BG} !important;
            box-shadow: 0 0 14px rgba(0,255,127,.5) !important;
            border-color: {NEON} !important;
        }}
        .stButton > button[kind="primary"] {{
            border-color: {NEON} !important; box-shadow: 0 0 10px rgba(0,255,127,.25) !important;
        }}
        .stTextInput input, .stNumberInput input, .stSelectbox div[data-baseweb] {{
            font-family: 'JetBrains Mono', monospace !important;
        }}
        h1, h2, h3, h4 {{ color: {NEON} !important; letter-spacing: 1px; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_matrix() -> None:
    """Matrix rain en fond — injecte dans le document parent.

    ``st.markdown`` retire les ``<script>`` : on passe donc obligatoirement par
    ``components.html``. Le canvas est ajoute une seule fois (garde par id).
    """
    _inject_html(
        """
    <script>
    const doc = window.parent.document;
    if (!doc.getElementById('nz-matrix')) {
      const c = doc.createElement('canvas'); c.id='nz-matrix';
      Object.assign(c.style,{position:'fixed',inset:'0',zIndex:'0',pointerEvents:'none',opacity:'0.13'});
      doc.body.prepend(c);
      const ctx=c.getContext('2d');
      const size=()=>{c.width=doc.documentElement.clientWidth;c.height=doc.documentElement.clientHeight;};
      size(); window.parent.addEventListener('resize',size);
      const chars='01<>/{}[]#$%&*0110'.split(''); const fs=14;
      let drops=Array(Math.ceil(c.width/fs)).fill(1);
      setInterval(()=>{
        ctx.fillStyle='rgba(5,10,8,0.08)'; ctx.fillRect(0,0,c.width,c.height);
        ctx.fillStyle='#00ff7f'; ctx.font=fs+'px monospace';
        drops.forEach((y,i)=>{
          ctx.fillText(chars[Math.floor(Math.random()*chars.length)], i*fs, y*fs);
          drops[i]=(y*fs>c.height && Math.random()>0.975)?0:y+1;
        });
      },55);
    }
    </script>
    """,
        height=0,
    )


def render_boot() -> None:
    """Sequence de boot : le banner ASCII se tape ligne par ligne + logs.

    Overlay plein ecran auto-destructeur (via ``components.html``) affiche une
    seule fois par session. ``pointer-events:none`` pour ne rien bloquer.
    """
    banner = (
        "NZ  NZOYI // C2  ------------------------------------------\n"
        " ___   ___  ___  ___ __\n"
        "| \\ | |_  / | | \\ / |\n"
        "|  \\| |/ / | | |  X  |\n"
        "|_|\\__/___\\|___/_/ \\_|\n"
    )
    logs = [
        "[OK] booting nzoyi kernel ......",
        "[OK] loading autonomous agents (7) ......",
        "[OK] q-table policy loaded ......",
        "[OK] rf-ids oracle linked ......",
        "[OK] link established // secure channel",
    ]
    payload = json.dumps({"banner": banner, "logs": logs})
    _inject_html(
        """
    <script>
    const doc = window.parent.document;
    if (!doc.getElementById('nz-boot')) {
      const data = %s;
      const ov = doc.createElement('div'); ov.id='nz-boot';
      Object.assign(ov.style,{position:'fixed',inset:'0',zIndex:'9999',
        background:'#050a08',color:'#00ff7f',fontFamily:'JetBrains Mono, monospace',
        fontSize:'14px',lineHeight:'1.5',padding:'8vh 8vw',whiteSpace:'pre',
        pointerEvents:'none',transition:'opacity .6s ease'});
      doc.body.appendChild(ov);
      const full = data.banner + "\\n" + data.logs.join("\\n") + "\\n";
      let i = 0;
      const type = () => {
        if (i <= full.length) {
          ov.textContent = full.slice(0, i) + "\\u2588";
          i += 2;
          setTimeout(type, 12);
        } else {
          setTimeout(()=>{ ov.style.opacity='0';
            setTimeout(()=>ov.remove(), 650); }, 550);
        }
      };
      type();
    }
    </script>
    """
        % payload,
        height=0,
    )


def render_clock() -> None:
    """Horloge live injectee dans ``#nz-clock`` (un seul interval)."""
    _inject_html(
        """
    <script>
    const win = window.parent;
    if (!win.__nzClock) {
      win.__nzClock = setInterval(()=>{
        const el = win.document.getElementById('nz-clock');
        if (el) {
          const d = new Date();
          el.textContent = d.toTimeString().slice(0,8);
        }
      }, 1000);
    }
    </script>
    """,
        height=0,
    )


def render_status_bar(cfg: dict | None, running: bool) -> None:
    """Barre de statut C2 en haut de page."""
    target = (cfg or {}).get("target", "192.168.100.11")
    mode = (cfg or {}).get("mode", "standby").upper()
    dry = "DRY-RUN" if (cfg or {}).get("dry_run", True) else "LIVE"
    status = "ONLINE" if running else "STANDBY"
    scol = NEON if running else AMBER
    sep = '<span class="sep">·</span>'
    st.markdown(
        f'<div class="nz-statusbar">'
        f'{icon("cpu", 14, NEON)} STATUS: <b style="color:{scol}">{status}</b> {sep}'
        f' TARGET: <b>{target}</b> {sep}'
        f' MODE: <b>{mode}</b> {sep}'
        f' LINK: <b>{dry}</b> {sep}'
        f' SEC: <b>LVL-1</b> {sep}'
        f' T<span style="color:{NEON_DIM}">//</span> <b id="nz-clock">--:--:--</b>'
        f'</div>',
        unsafe_allow_html=True,
    )


def bar(value: float, vmax: float, color: str) -> str:
    pct = max(0, min(100, (value / vmax) * 100 if vmax else 0))
    return (
        f'<div class="bar-wrap"><div class="bar-fill" '
        f'style="width:{pct:.0f}%;background:{color};box-shadow:0 0 6px {color};"></div></div>'
    )


def network_svg(cycle: int | None = None, active: str = "") -> str:
    """Topologie inline KALI ─ vboxnet0 ─ TARGET (sans emoji)."""
    cyc = f"CYCLE {cycle:02d}" if cycle is not None else "vboxnet0"
    kali_glow = NEON if active == "attack" else NEON_DIM
    tgt_glow = NEON if active == "evaluation" else NEON_DIM
    return f"""
    <svg viewBox="0 0 640 130" width="100%" style="max-height:130px">
      <defs>
        <style>
          @keyframes pk {{ 0%{{transform:translateX(0)}} 100%{{transform:translateX(300px)}} }}
          .pkt {{ animation: pk 2s linear infinite; }}
        </style>
      </defs>
      <rect x="10" y="30" width="160" height="70" rx="2" fill="{BG2}"
            stroke="{kali_glow}" stroke-width="2"/>
      <text x="90" y="54" fill="{NEON}" font-size="15" font-family="monospace"
            text-anchor="middle" font-weight="bold">[ KALI ]</text>
      <text x="90" y="72" fill="{TXT}" font-size="10" font-family="monospace"
            text-anchor="middle">192.168.100.10</text>
      <text x="90" y="88" fill="{NEON_DIM}" font-size="9" font-family="monospace"
            text-anchor="middle">7 agents · q-learning</text>

      <line x1="170" y1="65" x2="470" y2="65" stroke="{AMBER}"
            stroke-width="1.5" stroke-dasharray="4 4"/>
      <text x="320" y="55" fill="{AMBER}" font-size="10" font-family="monospace"
            text-anchor="middle">{cyc}</text>
      <circle class="pkt" cx="175" cy="65" r="4" fill="{AMBER}"/>
      <circle class="pkt" cx="175" cy="65" r="3" fill="{NEON}"
              style="animation-delay:1s"/>

      <rect x="470" y="30" width="160" height="70" rx="2" fill="{BG2}"
            stroke="{tgt_glow}" stroke-width="2"/>
      <text x="550" y="54" fill="{NEON}" font-size="15" font-family="monospace"
            text-anchor="middle" font-weight="bold">[ TARGET ]</text>
      <text x="550" y="72" fill="{TXT}" font-size="10" font-family="monospace"
            text-anchor="middle">192.168.100.11</text>
      <text x="550" y="88" fill="{NEON_DIM}" font-size="9" font-family="monospace"
            text-anchor="middle">rf-ids · apache/ssh/ftp</text>
    </svg>
    """


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
def rf_predict(strat: dict[str, float]) -> float:
    """Simulated Random-Forest intrusion score in [0,1] from strategy params."""
    score = 0.25
    if strat["ttl"] > 75:
        score += 0.15
    if strat["rate"] > 3:
        score += 0.20
    if strat["rate"] > 7:
        score += 0.15
    if strat["frag"] > 1:
        score -= 0.10
    if strat["jitter"] > 0.8:
        score -= 0.12
    if strat["pkt"] > 500:
        score += 0.10
    score += random.uniform(-0.05, 0.05)
    return max(0.0, min(1.0, score))


def features_from(strat: dict[str, float], score: float) -> dict[str, float]:
    return {
        "sttl": strat["ttl"],
        "rate": strat["rate"],
        "dload": strat["pkt"] * strat["rate"] * 8,
        "dmean": strat["pkt"] * 0.6,
        "sload": strat["rate"] * 40,
        "ct_srv": round(score * 10, 1),
    }


def init_learning_state(cfg: dict) -> None:
    st.session_state.sim = {
        "cfg": cfg,
        "phase": "recon",
        "agent_idx": 0,
        "cycle": 0,
        "cycles_total": cfg.get("cycles", 100),
        "q": {name: 0.0 for name in STRATEGIES},
        "epsilon": 0.30,
        "convergence": [],
        "total_detected": 0,
        "packets": 0,
        "terminal": [],
        "last": None,
        "agent_status": {a: "pending" for a in AGENTS},
        "done": False,
    }
    log("SYS", "=== NZOYI v%s // C2 ===" % VERSION)
    log("SYS", f"target={cfg['target']} profile={cfg['profile']}")


def log(tag: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.sim["terminal"].append((ts, tag, msg))
    # keep last 200 lines
    st.session_state.sim["terminal"] = st.session_state.sim["terminal"][-200:]


def run_recon_phase() -> None:
    s = st.session_state.sim
    s["agent_status"]["recon"] = "done"
    for line in [
        "nmap -sS -sV -T2 --max-rate 10 192.168.100.11",
        "22/tcp  open  ssh   OpenSSH 7.2p2",
        "80/tcp  open  http  Apache/2.4.49",
        "21/tcp  open  ftp   vsftpd 3.0.3",
    ]:
        log("RCN", line)
    s["agent_status"]["enumerator"] = "done"
    log("ENM", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10")
    log("ENM", "Server: Apache/2.4.49 (Unix)")
    s["agent_status"]["vulnerability"] = "done"
    log("VLN", "CVE-2021-41773 | CVSS 9.8 CRITICAL | Apache :80 | RCE")
    log("VLN", "CVE-2011-2523 | CVSS 9.8 CRITICAL | vsftpd :21 | Backdoor")
    s["phase"] = "learning"


def step_cycle() -> None:
    s = st.session_state.sim
    s["cycle"] += 1
    i = s["cycle"]
    s["agent_status"]["evasion"] = "running"

    # epsilon-greedy over strategies
    explore = random.random() < s["epsilon"]
    if explore:
        name = random.choice(list(STRATEGIES))
        mode = "E-EXPLORE"
    else:
        name = max(s["q"], key=s["q"].get)
        mode = "Q-EXPLOIT"
    strat = STRATEGIES[name]

    score = rf_predict(strat)
    detected = score >= 0.5
    reward = -1.0 if detected else 1.0

    # Q-update (alpha=0.3) + epsilon decay
    s["q"][name] += 0.3 * (reward - s["q"][name])
    s["epsilon"] = max(0.05, s["epsilon"] * 0.98)
    s["packets"] += int(strat["pkt"])

    if detected:
        s["total_detected"] += 1
    det_rate = s["total_detected"] / i

    s["convergence"].append({"cycle": i, "detection_rate": round(det_rate, 4),
                             "epsilon": round(s["epsilon"], 4)})
    s["last"] = {
        "strategy": name, "mode": mode, "strat": strat, "score": score,
        "detected": detected, "reward": reward,
        "features": features_from(strat, score),
    }
    s["agent_status"]["attack"] = "done"
    s["agent_status"]["evaluation"] = "done"
    s["agent_status"]["evasion"] = "done"

    # Terminal narrative
    log("EVA", f"[{mode}] -> {name} | rate={strat['rate']} pkt={strat['pkt']} "
               f"frag={strat['frag']} jit={strat['jitter']}")
    log("ATK", "192.168.100.11:80 <- GET /cgi-bin/.%2e/%2e%2e/etc/passwd")
    verdict = "[ALERT] ATTACK" if detected else "[OK] NORMAL"
    log("IDS", f"RF predict: {score*100:.1f}% -> {verdict}")
    log("RL", f"C{i:03d} | det={det_rate*100:.0f}% | e={s['epsilon']:.3f} "
              f"| r={'+1' if reward>0 else '-1'} | best={max(s['q'], key=s['q'].get)}")

    if i >= s["cycles_total"]:
        s["done"] = True
        s["phase"] = "done"
        log("SYS", f"=== MISSION COMPLETE // {s['cycles_total']} cycles ===")
        _persist_convergence()


def _persist_convergence() -> None:
    os.makedirs("results", exist_ok=True)
    with open("results/convergence.json", "w", encoding="utf-8") as fh:
        json.dump(st.session_state.sim["convergence"], fh, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 1 — MISSION CONTROL
# ═══════════════════════════════════════════════════════════════════════════
def page_mission_control() -> None:
    running = st.session_state.get("mission_running", False)

    # ── Target config ──
    st.markdown(
        f'<div class="nz-title">{icon("share-2", 16)} TARGET CONFIG</div>',
        unsafe_allow_html=True,
    )
    left, right = st.columns([1, 1.4])
    with left:
        target = st.text_input("Target IP", "192.168.100.11")
        st.text_input("Attacker IP", "192.168.100.10", disabled=True)
        st.text_input("Subnet", "192.168.100.0/24", disabled=True)
    with right:
        st.markdown(network_svg(), unsafe_allow_html=True)

    # ── Mission parameters ──
    with st.expander("MISSION PARAMETERS", expanded=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            profile = st.radio(
                "Attack profile",
                ["STEALTH", "BALANCED", "AGGRESSIVE"],
                captions=[
                    "SYN T2, rate 10/s, fragmentation, jitter 1-3s.",
                    "T3, rate standard. Compromis.",
                    "T4, rate elevee. Baseline.",
                ],
            )
        with c2:
            mode = st.radio(
                "Control mode",
                ["GUIDED", "AUTONOMOUS", "LEARNING"],
                index=2,
                captions=[
                    "Confirmation avant chaque agent.",
                    "Execution sequentielle, observation.",
                    "Boucle RL complete (N cycles).",
                ],
            )
        with c3:
            cycles = 100
            if mode == "LEARNING":
                cycles = st.number_input("Q-Learning cycles", 10, 1000, 100, 10)
            ids = st.selectbox(
                "IDS feedback",
                [
                    "IDS-ML (Random Forest) — API REST http://cible:5000",
                    "IDS-ML (Random Forest) — fichier predictions.json",
                    "Suricata — fichier eve.json",
                    "Simulation (pas d'IDS reel)",
                ],
                index=3,
            )
            ids_path = ""
            if "fichier" in ids:
                ids_path = st.text_input("IDS log path", "results/predictions.json")
            dry_run = st.checkbox("Dry run (simulation sans reseau)", value=True)

    # ── Mission brief ──
    profile_key = {"STEALTH": "stealth", "BALANCED": "default",
                   "AGGRESSIVE": "aggressive"}[profile]
    mode_key = {"GUIDED": "guided", "AUTONOMOUS": "autonomous",
                "LEARNING": "learning"}[mode]

    st.markdown(
        f'<div class="nz-title">{icon("list", 16)} MISSION BRIEF</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""<div class="recap">
        <div><span>TARGET</span><b>{target}</b></div>
        <div><span>PROFILE</span><b>{profile}</b></div>
        <div><span>MODE</span><b>{mode}</b></div>
        <div><span>CYCLES</span><b>{cycles if mode_key=='learning' else '—'}</b></div>
        <div><span>IDS FEEDBACK</span><b>{ids.split('—')[0].strip()}</b></div>
        <div><span>DRY RUN</span><b>{'YES' if dry_run else 'NO'}</b></div>
        </div>""",
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("DEPLOY MISSION", type="primary", width="stretch"):
        cfg = {
            "target": target, "profile": profile_key, "mode": mode_key,
            "cycles": int(cycles), "ids": ids, "ids_path": ids_path,
            "dry_run": dry_run,
        }
        os.makedirs("config", exist_ok=True)
        with open("config/mission_config.json", "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        st.session_state.mission_config = cfg
        st.session_state.mission_running = True
        st.session_state.page = "LIVE OPS"
        init_learning_state(cfg)
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 2 — LIVE OPS
# ═══════════════════════════════════════════════════════════════════════════
def page_live_operations() -> None:
    if "sim" not in st.session_state:
        cfg = st.session_state.get("mission_config")
        if not cfg and os.path.exists("config/mission_config.json"):
            cfg = json.load(open("config/mission_config.json", encoding="utf-8"))
        if not cfg:
            st.warning("Aucune mission configuree. Retour a MISSION CONTROL.")
            return
        init_learning_state(cfg)

    s = st.session_state.sim
    if s["phase"] == "recon":
        run_recon_phase()

    col_l, col_c, col_r = st.columns([1.2, 2, 1])

    # ── LEFT : agents + Q-table ──
    with col_l:
        _render_agents(s)
        _render_qtable(s)

    # ── CENTER : topology + terminal + convergence ──
    with col_c:
        active = "attack" if (s["last"] and not s["done"]) else ""
        st.markdown(network_svg(s["cycle"] or None, active), unsafe_allow_html=True)
        _render_terminal(s)
        _render_convergence(s)

    # ── RIGHT : IDS + strategy + reward + stats ──
    with col_r:
        _render_ids(s)
        _render_strategy(s)
        _render_reward(s)
        _render_stats(s)

    # ── Auto-advance loop ──
    paused = st.session_state.get("paused", False)
    if s["phase"] == "learning" and not s["done"] and not paused:
        step_cycle()
        speed = st.session_state.get("speed", 1.0)
        time.sleep(0.35 / speed)
        st.rerun()


def _render_agents(s: dict) -> None:
    st.markdown(
        f'<div class="nz-title">{icon("layers", 16)} AGENT CHAIN</div>',
        unsafe_allow_html=True,
    )
    badge = {"pending": "b-pending", "running": "b-run",
             "done": "b-done", "error": "b-err"}
    subinfo = {
        "recon": "4 ports found", "enumerator": "2 banners",
        "vulnerability": "2 CVEs mapped",
        "evasion": s["last"]["strategy"] if s["last"] else "—",
        "attack": "payload sent", "evaluation": "IDS polled",
    }
    rows = ""
    for a in AGENTS:
        stt = s["agent_status"][a]
        info = subinfo[a] if stt == "done" else ""
        col = NEON if stt == "done" else (AMBER if stt == "running" else TXT_DIM)
        rows += (
            f'<div style="display:flex;justify-content:space-between;'
            f'align-items:center;padding:5px 0;">'
            f'<span style="color:{TXT}">{icon(AGENT_ICONS[a], 15, col)} '
            f'<span style="letter-spacing:1px">{a}</span></span>'
            f'<span class="badge {badge[stt]}">{stt.upper()}</span></div>'
        )
        if info:
            rows += (f'<div style="color:{NEON_DIM};font-size:0.72rem;'
                     f'margin:-3px 0 4px 24px">{info}</div>')
    st.markdown(f'<div class="nz-card">{rows}</div>', unsafe_allow_html=True)


def _render_qtable(s: dict) -> None:
    st.markdown(
        f'<div class="nz-title">{icon("cpu", 16)} POLICY TABLE // TOP ACTIONS</div>',
        unsafe_allow_html=True,
    )
    ranked = sorted(s["q"].items(), key=lambda kv: kv[1], reverse=True)[:7]
    qmax = max((abs(v) for _, v in ranked), default=1.0) or 1.0
    rows = ""
    for i, (name, val) in enumerate(ranked):
        color = NEON if i == 0 else TXT
        star = ">" if i == 0 else " "
        rows += (
            f'<div style="color:{color};font-size:0.8rem;">'
            f'{star} {name:<14} {val:+.3f}</div>'
            f'{bar(abs(val), qmax, NEON if val>=0 else ALERT)}'
        )
    st.markdown(f'<div class="nz-card">{rows}</div>', unsafe_allow_html=True)


def _render_terminal(s: dict) -> None:
    tag_col = {
        "SYS": NEON, "RCN": NEON_DIM, "ENM": NEON_DIM, "VLN": AMBER,
        "ATK": AMBER, "IDS": NEON, "EVA": AMBER, "RL": NEON,
    }
    lines = ""
    for ts, tag, msg in s["terminal"][-80:]:
        col = tag_col.get(tag, TXT)
        if tag == "IDS" and "ATTACK" in msg:
            col = ALERT
        lines += (
            f'<span style="color:{TXT_DIM}">{ts}</span> '
            f'<span style="color:{col};font-weight:700">[{tag}]</span> '
            f'<span style="color:{TXT}">{msg}</span>\n'
        )
    lines += '<span class="cur">&#9608;</span>'
    st.markdown(
        f'<div class="nz-title">{icon("terminal", 16)} AGENT TERMINAL</div>',
        unsafe_allow_html=True,
    )
    st.markdown(f'<div class="term" id="nz-term">{lines}</div>', unsafe_allow_html=True)
    # Auto-scroll du terminal vers le bas (via document parent).
    _inject_html(
        """
    <script>
    const el = window.parent.document.getElementById('nz-term');
    if (el) { el.scrollTop = el.scrollHeight; }
    </script>
    """,
        height=0,
    )


def _render_convergence(s: dict) -> None:
    st.markdown(
        f'<div class="nz-title">{icon("bar-chart", 16)} CONVERGENCE // DETECTION RATE</div>',
        unsafe_allow_html=True,
    )
    conv = s["convergence"]
    if not conv:
        st.caption("En attente des premiers cycles...")
        return
    xs = [c["cycle"] for c in conv]
    ys = [c["detection_rate"] * 100 for c in conv]

    if HAS_PLOTLY:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=xs, y=ys, fill="tozeroy", mode="lines",
            line=dict(color=NEON, width=2), name="Detection %",
            fillcolor="rgba(0,255,127,.12)",
            hovertemplate="Cycle %{x}<br>%{y:.1f}%<extra></extra>",
        ))
        fig.add_hline(y=50, line_dash="dot", line_color=ALERT,
                      annotation_text="IDS threshold 50%")
        fig.update_layout(
            height=200, margin=dict(l=0, r=0, t=6, b=0),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=TXT, family="monospace", size=10),
            yaxis=dict(range=[0, 100], gridcolor="rgba(20,201,106,.12)"),
            xaxis=dict(gridcolor="rgba(20,201,106,.12)"),
        )
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    else:
        st.line_chart({"detection_%": ys}, height=200)


def _render_ids(s: dict) -> None:
    last = s["last"]
    title = f'<div class="nz-title">{icon("radar", 16)} IDS // RANDOM FOREST</div>'
    if not last:
        st.markdown(
            f'<div class="nz-card">{title}'
            f'<span style="color:{TXT_DIM}">En attente...</span></div>',
            unsafe_allow_html=True,
        )
        return
    detected = last["detected"]
    card = "nz-card-red" if detected else "nz-card-green"
    verdict = ("INTRUSION DETECTED" if detected else "TRAFFIC NORMAL")
    vcol = ALERT if detected else NEON
    feats = ""
    for name, val in last["features"].items():
        thr = FEATURE_THRESHOLDS.get(name)
        hot = thr is not None and val > thr
        col = ALERT if hot else NEON_DIM
        vmax = (thr * 1.5) if thr else max(val * 1.2, 1)
        feats += f'<div style="font-size:0.72rem;color:{TXT}">{name} = {val:.0f}</div>'
        feats += bar(val, vmax, col)
    conf = last["score"] * 100
    checks = s["cycle"]
    st.markdown(
        f'<div class="nz-card {card}">{title}'
        f'{feats}'
        f'<div style="font-size:0.72rem;color:{TXT};margin-top:4px">Confidence</div>'
        f'{bar(conf, 100, vcol)}'
        f'<div style="text-align:center;color:{vcol};font-weight:700;'
        f'letter-spacing:1px;text-shadow:0 0 8px {vcol};margin:6px 0">{verdict}</div>'
        f'<div style="font-size:0.72rem;color:{TXT_DIM};text-align:center">'
        f'ALERTS {s["total_detected"]} / CHECKS {checks}</div></div>',
        unsafe_allow_html=True,
    )


def _render_strategy(s: dict) -> None:
    last = s["last"]
    if not last:
        return
    strat = last["strat"]
    # green = stealthy, red = noisy
    params = [
        ("rate", strat["rate"], 10, True),
        ("packet", strat["pkt"], 1024, True),
        ("frag", strat["frag"], 4, False),
        ("jitter", strat["jitter"], 2.0, False),
        ("TTL", strat["ttl"], 128, True),
    ]
    rows = ""
    for name, val, vmax, noisy_high in params:
        ratio = val / vmax if vmax else 0
        noisy = ratio if noisy_high else (1 - ratio)
        col = ALERT if noisy > 0.6 else (AMBER if noisy > 0.3 else NEON)
        rows += f'<div style="font-size:0.72rem;color:{TXT}">{name} = {val}</div>'
        rows += bar(val, vmax, col)
    st.markdown(
        f'<div class="nz-card nz-card-amber">'
        f'<div class="nz-title">{icon("eye-off", 16, AMBER)} EVASION STRATEGY</div>'
        f'<div style="color:{NEON};font-weight:700;letter-spacing:1px">{last["strategy"]} '
        f'<span style="font-size:0.7rem;color:{NEON_DIM}">[{last["mode"]}]</span></div>'
        f'{rows}</div>',
        unsafe_allow_html=True,
    )


def _render_reward(s: dict) -> None:
    last = s["last"]
    if not last:
        return
    if last["reward"] > 0:
        st.markdown('<div class="reward reward-ok">REWARD: +1.0 // EVASION SUCCESS</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<div class="reward reward-bad">REWARD: -1.0 // DETECTED</div>',
                    unsafe_allow_html=True)


def _render_stats(s: dict) -> None:
    det_rate = (s["total_detected"] / s["cycle"] * 100) if s["cycle"] else 0
    rate_col = NEON if det_rate < 20 else (ALERT if det_rate > 40 else AMBER)
    c1, c2 = st.columns(2)
    c1.metric("Cycle", f"{s['cycle']}/{s['cycles_total']}")
    c2.metric("Detection", f"{det_rate:.0f}%")
    c3, c4 = st.columns(2)
    c3.metric("Epsilon", f"{s['epsilon']:.3f}")
    c4.metric("Packets", f"{s['packets']}")
    st.markdown(
        f'<div style="height:4px;background:{rate_col};'
        f'box-shadow:0 0 8px {rate_col}"></div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# APP SHELL
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    st.set_page_config(page_title="NZOYI // C2", page_icon=None, layout="wide")
    inject_css()
    render_matrix()
    render_clock()

    # Boot sequence : une seule fois par session.
    if not st.session_state.get("booted", False):
        render_boot()
        st.session_state.booted = True

    st.session_state.setdefault("page", "MISSION CONTROL")
    st.session_state.setdefault("speed", 1.0)
    st.session_state.setdefault("paused", False)

    running = st.session_state.get("mission_running", False)
    render_status_bar(st.session_state.get("mission_config"), running)

    with st.sidebar:
        st.markdown(
            f'<h2 style="color:{NEON};letter-spacing:2px;display:flex;'
            f'align-items:center;gap:8px">{icon("cpu", 22)} NZOYI</h2>',
            unsafe_allow_html=True,
        )
        st.caption(f"v{VERSION} // C2 CONSOLE")
        page = st.radio("Navigation", ["MISSION CONTROL", "LIVE OPS"],
                        index=0 if st.session_state.page == "MISSION CONTROL" else 1)
        st.session_state.page = page

        st.divider()
        st.session_state.speed = {
            "0.5x": 0.5, "1x": 1.0, "2x": 2.0, "4x": 4.0
        }[st.select_slider("Speed", ["0.5x", "1x", "2x", "4x"], value="1x")]

        cc1, cc2 = st.columns(2)
        if cc1.button("RESUME" if st.session_state.paused else "PAUSE",
                      width="stretch"):
            st.session_state.paused = not st.session_state.paused
            st.rerun()
        if cc2.button("ABORT", width="stretch"):
            for k in ("sim", "mission_running", "mission_config"):
                st.session_state.pop(k, None)
            st.session_state.paused = False
            st.rerun()

        if "sim" in st.session_state:
            st.markdown(
                f'<div style="text-align:center;font-size:2.4rem;color:{NEON};'
                f'font-weight:700;text-shadow:0 0 12px rgba(0,255,127,.4)">'
                f'{st.session_state.sim["cycle"]}</div>'
                f'<div style="text-align:center;color:{TXT_DIM};'
                f'font-size:0.7rem;letter-spacing:2px">CYCLES</div>',
                unsafe_allow_html=True,
            )

    if st.session_state.page == "MISSION CONTROL":
        page_mission_control()
    else:
        page_live_operations()


if __name__ == "__main__":
    main()
else:
    main()
