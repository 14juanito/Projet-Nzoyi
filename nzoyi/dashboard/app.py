"""
NZOYI — Streamlit Cockpit (standalone).

Cockpit de contrôle du système multi-agent :
  Page 1 · Mission Control  — configuration + lancement
  Page 2 · Live Operations  — exécution temps réel (simulation dry-run)

Lancement :
  python3 nzoyi/dashboard/app.py          # auto (venv + streamlit)
  streamlit run nzoyi/dashboard/app.py
  ./run_dashboard.sh
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

# ── Optional plotly (fallback to st.line_chart) ──────────────────────────────
try:
    import plotly.graph_objects as go

    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

VERSION = "0.1.0"

# ── Palette ──────────────────────────────────────────────────────────────────
GOLD = "#F5A623"
AMBER = "#E8920D"
GREEN = "#00FF88"
RED = "#FF3366"
CYAN = "#00E5FF"
PURPLE = "#B266FF"
ORANGE = "#FF8833"
BG = "#020408"
BG2 = "#0a0e17"
TXT = "#C0C8D4"

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
AGENT_ICONS = {
    "recon": "🔍", "enumerator": "📇", "vulnerability": "🧬",
    "evasion": "🥷", "attack": "💥", "evaluation": "🛡️",
}

# UNSW-NB15 features shown in the IDS panel and their "alert" thresholds.
FEATURE_THRESHOLDS = {"sttl": 80, "rate": 5, "dload": 5000, "dmean": 300}


# ═══════════════════════════════════════════════════════════════════════════
# CSS / THEME
# ═══════════════════════════════════════════════════════════════════════════
def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        .stApp {{ background: {BG}; }}
        /* Matrix rain — very subtle */
        .matrix {{
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            z-index: -1; opacity: 0.035; overflow: hidden; pointer-events: none;
            font-family: monospace; color: {GREEN}; font-size: 14px;
        }}
        .matrix span {{
            position: absolute; top: -10%;
            animation: fall linear infinite;
        }}
        @keyframes fall {{ to {{ transform: translateY(110vh); }} }}

        .nz-card {{
            background: {BG2}; border: 1px solid rgba(245,166,35,0.25);
            border-radius: 10px; padding: 14px 16px; margin-bottom: 14px;
            box-shadow: 0 0 15px rgba(245,166,35,0.10);
        }}
        .nz-card-green {{ border-color: rgba(0,255,136,0.45);
            box-shadow: 0 0 18px rgba(0,255,136,0.15); }}
        .nz-card-red {{ border-color: rgba(255,51,102,0.55);
            box-shadow: 0 0 18px rgba(255,51,102,0.18); }}
        .nz-card-amber {{ border-color: rgba(232,146,13,0.45); }}
        .nz-title {{ color: {GOLD}; font-weight: 700; font-size: 0.95rem;
            letter-spacing: 0.5px; margin-bottom: 8px; }}

        .dot {{ height: 11px; width: 11px; border-radius: 50%;
            display: inline-block; margin-right: 7px; }}
        .dot-run {{ background: {GREEN}; box-shadow: 0 0 10px {GREEN};
            animation: pulse 1.1s infinite; }}
        .dot-idle {{ background: {RED}; box-shadow: 0 0 8px {RED}; }}
        @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.35}} }}

        .badge {{ display:inline-block; padding:2px 9px; border-radius:6px;
            font-size:0.72rem; font-weight:700; font-family:monospace; }}
        .b-pending {{ background:#1b2130; color:{TXT}; }}
        .b-run {{ background:rgba(245,166,35,0.18); color:{GOLD}; }}
        .b-done {{ background:rgba(0,255,136,0.15); color:{GREEN}; }}
        .b-err {{ background:rgba(255,51,102,0.18); color:{RED}; }}

        .bar-wrap {{ background:#11161f; border-radius:4px; height:9px;
            width:100%; overflow:hidden; margin:3px 0 8px 0; }}
        .bar-fill {{ height:100%; border-radius:4px; }}

        .term {{ background:#010308; border:1px solid rgba(245,166,35,0.2);
            border-radius:8px; padding:10px 12px; font-family:monospace;
            font-size:11px; line-height:1.55; height:340px; overflow-y:auto;
            white-space:pre-wrap; }}
        .term::-webkit-scrollbar {{ width:6px; }}
        .term::-webkit-scrollbar-thumb {{ background:{AMBER}; border-radius:3px; }}

        .reward-ok {{ background:rgba(0,255,136,0.14); color:{GREEN};
            border:1px solid {GREEN}; text-shadow:0 0 8px {GREEN}; }}
        .reward-bad {{ background:rgba(255,51,102,0.14); color:{RED};
            border:1px solid {RED}; text-shadow:0 0 8px {RED}; }}
        .reward {{ padding:8px; border-radius:8px; text-align:center;
            font-weight:700; font-family:monospace; margin:6px 0; }}

        .recap {{ font-family:monospace; font-size:0.85rem; background:{BG2};
            border:1px solid rgba(245,166,35,0.3); border-radius:8px; padding:12px; }}
        .recap div {{ display:flex; justify-content:space-between; padding:3px 0;
            border-bottom:1px dashed rgba(255,255,255,0.06); }}
        .recap b {{ color:{GOLD}; }}
        </style>
        <div class="matrix">{_matrix_spans()}</div>
        """,
        unsafe_allow_html=True,
    )


def _matrix_spans(n: int = 26) -> str:
    rng = random.Random(7)
    spans = []
    for _ in range(n):
        left = rng.randint(0, 100)
        dur = rng.uniform(4, 12)
        delay = rng.uniform(0, 8)
        col = "".join(rng.choice("01") for _ in range(rng.randint(8, 20)))
        spans.append(
            f'<span style="left:{left}%;animation-duration:{dur:.1f}s;'
            f'animation-delay:{delay:.1f}s;">{col}</span>'
        )
    return "".join(spans)


def bar(value: float, vmax: float, color: str) -> str:
    pct = max(0, min(100, (value / vmax) * 100 if vmax else 0))
    return (
        f'<div class="bar-wrap"><div class="bar-fill" '
        f'style="width:{pct:.0f}%;background:{color};"></div></div>'
    )


def network_svg(cycle: int | None = None, active: str = "") -> str:
    """Inline responsive SVG topology KALI ─ vboxnet0 ─ TARGET."""
    cyc = f"CYCLE {cycle:02d}" if cycle is not None else "vboxnet0"
    kali_glow = "#F5A623" if active == "attack" else "#7a5a10"
    tgt_glow = "#00FF88" if active == "evaluation" else "#0a5a35"
    return f"""
    <svg viewBox="0 0 640 130" width="100%" style="max-height:130px">
      <defs>
        <style>
          @keyframes pk {{ 0%{{transform:translateX(0)}} 100%{{transform:translateX(300px)}} }}
          .pkt {{ animation: pk 2s linear infinite; }}
        </style>
      </defs>
      <rect x="10" y="30" width="160" height="70" rx="8" fill="{BG2}"
            stroke="{kali_glow}" stroke-width="2"/>
      <text x="90" y="52" fill="{GOLD}" font-size="15" font-family="monospace"
            text-anchor="middle" font-weight="bold">🗡 KALI</text>
      <text x="90" y="70" fill="{TXT}" font-size="10" font-family="monospace"
            text-anchor="middle">192.168.100.10</text>
      <text x="90" y="86" fill="{CYAN}" font-size="9" font-family="monospace"
            text-anchor="middle">7 agents · Q-Learning</text>

      <line x1="170" y1="65" x2="470" y2="65" stroke="{AMBER}"
            stroke-width="1.5" stroke-dasharray="4 4"/>
      <text x="320" y="55" fill="{AMBER}" font-size="10" font-family="monospace"
            text-anchor="middle">{cyc}</text>
      <circle class="pkt" cx="175" cy="65" r="4" fill="{ORANGE}"/>
      <circle class="pkt" cx="175" cy="65" r="3" fill="{GREEN}"
              style="animation-delay:1s"/>

      <rect x="470" y="30" width="160" height="70" rx="8" fill="{BG2}"
            stroke="{tgt_glow}" stroke-width="2"/>
      <text x="550" y="52" fill="{GREEN}" font-size="15" font-family="monospace"
            text-anchor="middle" font-weight="bold">🎯 TARGET</text>
      <text x="550" y="70" fill="{TXT}" font-size="10" font-family="monospace"
            text-anchor="middle">192.168.100.11</text>
      <text x="550" y="86" fill="{PURPLE}" font-size="9" font-family="monospace"
            text-anchor="middle">RF-IDS · Apache/SSH/FTP</text>
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
    log("SYS", "═══ NZOYI v%s ═══" % VERSION)
    log("SYS", f"Target: {cfg['target']} | Profile: {cfg['profile']}")


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
        mode = "ε-EXPLORE"
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
    log("EVA", f"[{mode}] → {name} | rate={strat['rate']} pkt={strat['pkt']} "
               f"frag={strat['frag']} jit={strat['jitter']}")
    log("ATK", "192.168.100.11:80 ← GET /cgi-bin/.%2e/%2e%2e/etc/passwd")
    verdict = "🚨 ATTACK" if detected else "✅ NORMAL"
    log("IDS", f"RF predict: {score*100:.1f}% → {verdict}")
    log("RL", f"C{i:03d} | det={det_rate*100:.0f}% | ε={s['epsilon']:.3f} "
              f"| r={'+1' if reward>0 else '-1'} | best={max(s['q'], key=s['q'].get)}")

    if i >= s["cycles_total"]:
        s["done"] = True
        s["phase"] = "done"
        log("SYS", f"═══ MISSION COMPLETE · {s['cycles_total']} cycles ═══")
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
    dot = "dot-run" if running else "dot-idle"
    status = "RUNNING" if running else "STANDBY"

    st.code(
        "🐝 NZOYI v%s — Multi-Agent IDS Resilience Framework" % VERSION,
        language=None,
    )
    st.markdown(
        f'<div class="nz-card"><span class="dot {dot}"></span>'
        f'<b style="color:{GOLD}">SYSTEM STATUS: {status}</b></div>',
        unsafe_allow_html=True,
    )

    # ── Section 2 : Network Configuration ──
    st.markdown(f'<div class="nz-title">🌐 NETWORK CONFIGURATION</div>',
                unsafe_allow_html=True)
    left, right = st.columns([1, 1.4])
    with left:
        target = st.text_input("Target IP", "192.168.100.11")
        st.text_input("Attacker IP", "192.168.100.10", disabled=True)
        st.text_input("Subnet", "192.168.100.0/24", disabled=True)
    with right:
        st.markdown(network_svg(), unsafe_allow_html=True)

    # ── Section 3 : Mission Parameters ──
    with st.expander("⚙️ MISSION PARAMETERS", expanded=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            profile = st.radio(
                "Profil d'attaque",
                ["🥷 Stealth", "⚖️ Balanced", "⚡ Aggressive"],
                captions=[
                    "SYN T2, rate 10/s, fragmentation, jitter 1-3s.",
                    "Version T3, rate standard. Compromis.",
                    "Version T4, rate élevée. Baseline.",
                ],
            )
        with c2:
            mode = st.radio(
                "Mode de pilotage",
                ["🎮 Guidé", "🤖 Autonome", "🧠 Apprentissage"],
                index=2,
                captions=[
                    "Confirmation avant chaque agent.",
                    "Exécution séquentielle, tu observes.",
                    "Boucle RL complète (N cycles).",
                ],
            )
        with c3:
            cycles = 100
            if "Apprentissage" in mode:
                cycles = st.number_input("Cycles Q-Learning", 10, 1000, 100, 10)
            ids = st.selectbox(
                "IDS Feedback",
                [
                    "🤖 IDS-ML (Random Forest) — API REST http://cible:5000",
                    "📄 IDS-ML (Random Forest) — fichier predictions.json",
                    "🔒 Suricata — fichier eve.json",
                    "⚠️ Simulation (pas d'IDS réel)",
                ],
                index=3,
            )
            ids_path = ""
            if "fichier" in ids:
                ids_path = st.text_input("Chemin logs IDS", "results/predictions.json")
            dry_run = st.checkbox("Dry Run (simulation sans réseau)", value=True)

    # ── Section 4 : Recap ──
    profile_key = {"🥷 Stealth": "stealth", "⚖️ Balanced": "default",
                   "⚡ Aggressive": "aggressive"}[profile]
    mode_key = {"🎮 Guidé": "guided", "🤖 Autonome": "autonomous",
                "🧠 Apprentissage": "learning"}[mode]

    st.markdown('<div class="nz-title">📋 RÉCAPITULATIF</div>', unsafe_allow_html=True)
    st.markdown(
        f"""<div class="recap">
        <div><span>Cible</span><b>{target}</b></div>
        <div><span>Profil</span><b>{profile}</b></div>
        <div><span>Mode</span><b>{mode}</b></div>
        <div><span>Cycles</span><b>{cycles if mode_key=='learning' else '—'}</b></div>
        <div><span>IDS Feedback</span><b>{ids.split('—')[0].strip()}</b></div>
        <div><span>Dry Run</span><b>{'Oui' if dry_run else 'Non'}</b></div>
        </div>""",
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("▶  LANCER LA MISSION", type="primary", use_container_width=True):
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
        st.session_state.page = "🐝 Live Operations"
        init_learning_state(cfg)
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 2 — LIVE OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
def page_live_operations() -> None:
    if "sim" not in st.session_state:
        cfg = st.session_state.get("mission_config")
        if not cfg and os.path.exists("config/mission_config.json"):
            cfg = json.load(open("config/mission_config.json", encoding="utf-8"))
        if not cfg:
            st.warning("Aucune mission configurée. Va dans 🎯 Mission Control.")
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
    st.markdown('<div class="nz-title">AGENTS PIPELINE</div>', unsafe_allow_html=True)
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
        rows += (
            f'<div style="display:flex;justify-content:space-between;'
            f'align-items:center;padding:5px 0;">'
            f'<span>{AGENT_ICONS[a]} {a}</span>'
            f'<span class="badge {badge[stt]}">{stt.upper()}</span></div>'
        )
        if info:
            rows += f'<div style="color:{CYAN};font-size:0.72rem;margin:-3px 0 4px 22px">{info}</div>'
    st.markdown(f'<div class="nz-card">{rows}</div>', unsafe_allow_html=True)


def _render_qtable(s: dict) -> None:
    st.markdown('<div class="nz-title">Q-TABLE RANKINGS</div>', unsafe_allow_html=True)
    ranked = sorted(s["q"].items(), key=lambda kv: kv[1], reverse=True)[:7]
    qmax = max((abs(v) for _, v in ranked), default=1.0) or 1.0
    rows = ""
    for i, (name, val) in enumerate(ranked):
        color = GREEN if i == 0 else TXT
        star = "★" if i == 0 else " "
        rows += (
            f'<div style="color:{color};font-size:0.8rem;">'
            f'{star} {name:<14} {val:+.3f}</div>'
            f'{bar(abs(val), qmax, GREEN if val>=0 else RED)}'
        )
    st.markdown(f'<div class="nz-card">{rows}</div>', unsafe_allow_html=True)


def _render_terminal(s: dict) -> None:
    tag_col = {
        "SYS": GOLD, "RCN": CYAN, "ENM": PURPLE, "VLN": ORANGE,
        "ATK": ORANGE, "IDS": GREEN, "EVA": AMBER, "RL": GOLD,
    }
    lines = ""
    for ts, tag, msg in s["terminal"][-80:]:
        col = tag_col.get(tag, TXT)
        if tag == "IDS" and "ATTACK" in msg:
            col = RED
        lines += (
            f'<span style="color:#4a5568">{ts}</span> '
            f'<span style="color:{col};font-weight:700">[{tag}]</span> '
            f'<span style="color:{TXT}">{msg}</span>\n'
        )
    st.markdown('<div class="nz-title">AGENT TERMINAL</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="term">{lines}</div>', unsafe_allow_html=True)


def _render_convergence(s: dict) -> None:
    st.markdown('<div class="nz-title">📉 Convergence — Detection Rate</div>',
                unsafe_allow_html=True)
    conv = s["convergence"]
    if not conv:
        st.caption("En attente des premiers cycles…")
        return
    xs = [c["cycle"] for c in conv]
    ys = [c["detection_rate"] * 100 for c in conv]

    if HAS_PLOTLY:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=xs, y=ys, fill="tozeroy", mode="lines",
            line=dict(color=GOLD, width=2), name="Détection %",
            hovertemplate="Cycle %{x}<br>%{y:.1f}%<extra></extra>",
        ))
        fig.add_hline(y=50, line_dash="dot", line_color=RED,
                      annotation_text="Seuil IDS 50%")
        fig.update_layout(
            height=200, margin=dict(l=0, r=0, t=6, b=0),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=TXT, family="monospace", size=10),
            yaxis=dict(range=[0, 100], gridcolor="#1a2030"),
            xaxis=dict(gridcolor="#1a2030"),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.line_chart({"detection_%": ys}, height=200)


def _render_ids(s: dict) -> None:
    last = s["last"]
    if not last:
        st.markdown('<div class="nz-card"><div class="nz-title">🛡️ IDS-ML Random Forest</div>'
                    '<span style="color:#666">En attente…</span></div>',
                    unsafe_allow_html=True)
        return
    detected = last["detected"]
    card = "nz-card-red" if detected else "nz-card-green"
    verdict = ("🚨 INTRUSION DETECTED" if detected else "✅ TRAFFIC NORMAL")
    vcol = RED if detected else GREEN
    feats = ""
    for name, val in last["features"].items():
        thr = FEATURE_THRESHOLDS.get(name)
        hot = thr is not None and val > thr
        col = RED if hot else CYAN
        vmax = (thr * 1.5) if thr else max(val * 1.2, 1)
        feats += f'<div style="font-size:0.72rem;color:{TXT}">{name} = {val:.0f}</div>'
        feats += bar(val, vmax, col)
    conf = last["score"] * 100
    checks = s["cycle"]
    st.markdown(
        f'<div class="nz-card {card}"><div class="nz-title">🛡️ IDS-ML Random Forest</div>'
        f'{feats}'
        f'<div style="font-size:0.72rem;color:{TXT};margin-top:4px">Confidence</div>'
        f'{bar(conf, 100, vcol)}'
        f'<div style="text-align:center;color:{vcol};font-weight:700;'
        f'text-shadow:0 0 8px {vcol};margin:6px 0">{verdict}</div>'
        f'<div style="font-size:0.72rem;color:#888;text-align:center">'
        f'Alerts {s["total_detected"]} / Checks {checks}</div></div>',
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
        col = RED if noisy > 0.6 else (AMBER if noisy > 0.3 else GREEN)
        rows += f'<div style="font-size:0.72rem;color:{TXT}">{name} = {val}</div>'
        rows += bar(val, vmax, col)
    st.markdown(
        f'<div class="nz-card nz-card-amber"><div class="nz-title">EVASION STRATEGY</div>'
        f'<div style="color:{GOLD};font-weight:700">{last["strategy"]} '
        f'<span style="font-size:0.7rem;color:{CYAN}">[{last["mode"]}]</span></div>'
        f'{rows}</div>',
        unsafe_allow_html=True,
    )


def _render_reward(s: dict) -> None:
    last = s["last"]
    if not last:
        return
    if last["reward"] > 0:
        st.markdown('<div class="reward reward-ok">REWARD: +1.0 · EVASION SUCCESS</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<div class="reward reward-bad">REWARD: -1.0 · DETECTED</div>',
                    unsafe_allow_html=True)


def _render_stats(s: dict) -> None:
    det_rate = (s["total_detected"] / s["cycle"] * 100) if s["cycle"] else 0
    rate_col = GREEN if det_rate < 20 else (RED if det_rate > 40 else AMBER)
    c1, c2 = st.columns(2)
    c1.metric("Cycle", f"{s['cycle']}/{s['cycles_total']}")
    c2.metric("Detection", f"{det_rate:.0f}%")
    c3, c4 = st.columns(2)
    c3.metric("Epsilon", f"{s['epsilon']:.3f}")
    c4.metric("Packets", f"{s['packets']}")
    st.markdown(
        f'<div style="height:4px;background:{rate_col};border-radius:2px;'
        f'box-shadow:0 0 8px {rate_col}"></div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# APP SHELL
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    st.set_page_config(page_title="NZOYI Cockpit", page_icon="🐝", layout="wide")
    inject_css()

    st.session_state.setdefault("page", "🎯 Mission Control")
    st.session_state.setdefault("speed", 1.0)
    st.session_state.setdefault("paused", False)

    with st.sidebar:
        st.markdown(f'<h2 style="color:{GOLD};font-family:monospace">🐝 NZOYI</h2>',
                    unsafe_allow_html=True)
        page = st.radio("Navigation", ["🎯 Mission Control", "🐝 Live Operations"],
                        index=0 if st.session_state.page == "🎯 Mission Control" else 1)
        st.session_state.page = page

        st.divider()
        st.session_state.speed = {
            "0.5x": 0.5, "1x": 1.0, "2x": 2.0, "4x": 4.0
        }[st.select_slider("Vitesse", ["0.5x", "1x", "2x", "4x"], value="1x")]

        cc1, cc2 = st.columns(2)
        if cc1.button("⏸ Pause" if not st.session_state.paused else "▶ Resume",
                      use_container_width=True):
            st.session_state.paused = not st.session_state.paused
            st.rerun()
        if cc2.button("⟳ Reset", use_container_width=True):
            for k in ("sim", "mission_running", "mission_config"):
                st.session_state.pop(k, None)
            st.session_state.paused = False
            st.rerun()

        if "sim" in st.session_state:
            st.markdown(
                f'<div style="text-align:center;font-size:2.4rem;color:{GOLD};'
                f'font-family:monospace;font-weight:700">'
                f'{st.session_state.sim["cycle"]}</div>'
                f'<div style="text-align:center;color:#888;font-size:0.7rem">CYCLES</div>',
                unsafe_allow_html=True,
            )

    if st.session_state.page == "🎯 Mission Control":
        page_mission_control()
    else:
        page_live_operations()


if __name__ == "__main__":
    main()
else:
    main()
