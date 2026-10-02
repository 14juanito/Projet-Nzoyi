"""
NZOYI — Console C2 Streamlit (visualiseur pur).

Esthetique "cyber ops console" : fond noir, neon vert, monospace, panneaux a
coins en crochets, matrix rain + scanlines CRT.

Ce dashboard ne simule RIEN : il lit en continu les fichiers d'etat ecrits par
le CLI (main.py + orchestrator) dans results/ :
  - results/run_state.json      agent courant + statut
  - results/evasion_state.json  cycle / epsilon / alerts / p_detect
  - results/ptt.json            arbre du Pentest Tree
  - results/convergence.json    courbe de detection

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
import time

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

# Répertoire des fichiers d'état écrits par le CLI.
RESULTS = Path("results")

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


# ═══════════════════════════════════════════════════════════════════════════
# LECTURE D'ÉTAT (fichiers écrits par le CLI)
# ═══════════════════════════════════════════════════════════════════════════
def _read_json(name: str, default=None):
    """Lit results/<name> en tolérant l'absence, un JSON partiel ou corrompu."""
    try:
        with open(RESULTS / name, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError):
        return default


def _autorefresh(interval_ms: int = 1500) -> None:
    """Relit les fichiers d'état toutes les ~1.5s (lecture continue).

    Utilise ``st_autorefresh`` si le composant est installé, sinon repli sur un
    ``time.sleep`` + ``st.rerun``. Suspendu si l'utilisateur met en pause.
    """
    if st.session_state.get("paused_refresh"):
        return
    try:
        from streamlit_autorefresh import st_autorefresh

        st_autorefresh(interval=interval_ms, key="nz_refresh")
    except Exception:
        time.sleep(interval_ms / 1000)
        st.rerun()


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


def render_status_bar(run_state: dict | None, running: bool) -> None:
    """Barre de statut C2 en haut de page (dérivée de run_state.json)."""
    rs = run_state or {}
    target = rs.get("target", "192.168.100.11")
    agent = (rs.get("current_agent") or "standby").upper()
    status = "ONLINE" if running else ("DONE" if rs else "STANDBY")
    scol = NEON if running else AMBER
    sep = '<span class="sep">·</span>'
    st.markdown(
        f'<div class="nz-statusbar">'
        f'{icon("cpu", 14, NEON)} STATUS: <b style="color:{scol}">{status}</b> {sep}'
        f' TARGET: <b>{target}</b> {sep}'
        f' AGENT: <b>{agent}</b> {sep}'
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
    """Topologie inline KALI ─ nzoyi-lab ─ TARGET (sans emoji)."""
    cyc = f"CYCLE {cycle:02d}" if cycle is not None else "nzoyi-lab"
    kali_glow = NEON if active in ("evasion", "attack") else NEON_DIM
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
# PANNEAUX (lecture seule — alimentés par les fichiers results/*.json)
# ═══════════════════════════════════════════════════════════════════════════
def render_agents(run_state: dict | None) -> None:
    """AGENT CHAIN dérivée de run_state (agent courant + statut)."""
    st.markdown(
        f'<div class="nz-title">{icon("layers", 16)} AGENT CHAIN</div>',
        unsafe_allow_html=True,
    )
    badge = {"pending": "b-pending", "running": "b-run", "done": "b-done", "error": "b-err"}
    rs = run_state or {}
    current = rs.get("current_agent")
    status = rs.get("status", "")
    done_all = status == "complete"
    idx = AGENTS.index(current) if current in AGENTS else -1
    summary = rs.get("result", {}) or {}
    rows = ""
    for i, a in enumerate(AGENTS):
        if done_all:
            stt = "done"
        elif idx == -1:
            stt = "pending"
        elif i < idx:
            stt = "done"
        elif i == idx:
            stt = status if status in ("running", "done", "error") else "running"
        else:
            stt = "pending"
        col = NEON if stt == "done" else (AMBER if stt == "running" else TXT_DIM)
        rows += (
            f'<div style="display:flex;justify-content:space-between;'
            f'align-items:center;padding:5px 0;">'
            f'<span style="color:{TXT}">{icon(AGENT_ICONS[a], 15, col)} '
            f'<span style="letter-spacing:1px">{a}</span></span>'
            f'<span class="badge {badge[stt]}">{stt.upper()}</span></div>'
        )
        if i == idx and stt == "done" and summary:
            info = " · ".join(f"{k}={v}" for k, v in summary.items())
            rows += (f'<div style="color:{NEON_DIM};font-size:0.72rem;'
                     f'margin:-3px 0 4px 24px">{info}</div>')
    st.markdown(f'<div class="nz-card">{rows}</div>', unsafe_allow_html=True)


def render_ptt(ptt: dict | None) -> None:
    """PENTEST TREE — rendu de results/ptt.json (arbre ou résumé)."""
    st.markdown(
        f'<div class="nz-title">{icon("share-2", 16)} PENTEST TREE // PTT</div>',
        unsafe_allow_html=True,
    )
    if not ptt:
        st.markdown(
            f'<div class="nz-card"><span style="color:{TXT_DIM}">'
            f'PTT vide — en attente d\'un run…</span></div>',
            unsafe_allow_html=True,
        )
        return

    target = ptt.get("target", "—")
    nodes = ptt.get("nodes")
    if isinstance(nodes, list):  # arbre complet (to_dict)
        node_count = len(nodes)
        agents = sorted({n.get("agent", "?") for n in nodes})
        kinds = sorted({n.get("kind", "?") for n in nodes})
        vulns = len(ptt.get("vulnerabilities", []))
    else:  # résumé (summary)
        node_count = ptt.get("node_count", 0)
        agents = ptt.get("agents", [])
        kinds = ptt.get("kinds", [])
        vulns = None

    agent_rows = "".join(
        f'<div style="color:{TXT};font-size:0.8rem;padding:2px 0">'
        f'{icon(AGENT_ICONS.get(a, "circle"), 14, NEON_DIM)} {a}</div>'
        for a in agents
    )
    meta = f'nodes={node_count} · kinds={len(kinds)}'
    if vulns is not None:
        meta += f' · vulns={vulns}'
    st.markdown(
        f'<div class="nz-card">'
        f'<div style="color:{NEON};font-size:.8rem">TARGET <b>{target}</b></div>'
        f'<div style="color:{TXT};font-size:.75rem;margin-bottom:6px">{meta}</div>'
        f'{agent_rows}</div>',
        unsafe_allow_html=True,
    )


def render_convergence(convergence: list) -> None:
    """Courbe de convergence lue depuis results/convergence.json."""
    st.markdown(
        f'<div class="nz-title">{icon("bar-chart", 16)} CONVERGENCE // DETECTION RATE</div>',
        unsafe_allow_html=True,
    )
    if not convergence:
        st.caption("En attente des premiers cycles…")
        return
    xs = [c.get("cycle") for c in convergence]
    ys = [c.get("detection_rate", 0) * 100 for c in convergence]

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


def render_evasion(evasion_state: dict | None) -> None:
    """État d'évasion (cycle/epsilon/alerts/p_detect) lu depuis evasion_state.json."""
    title = f'<div class="nz-title">{icon("eye-off", 16, AMBER)} EVASION STATE</div>'
    if not evasion_state:
        st.markdown(
            f'<div class="nz-card nz-card-amber">{title}'
            f'<span style="color:{TXT_DIM}">Pas de boucle RL active.</span></div>',
            unsafe_allow_html=True,
        )
        return

    detected = evasion_state.get("detected")
    card = "nz-card-red" if detected else "nz-card-green"
    p = evasion_state.get("p_detect") or 0.0
    st.markdown(
        f'<div class="nz-card {card}">{title}'
        f'<div style="color:{NEON};font-weight:700;letter-spacing:1px">'
        f'ACTION: {evasion_state.get("last_action", "—")}</div>'
        f'<div style="font-size:.72rem;color:{TXT};margin-top:4px">p_detect = {p:.2f}</div>'
        f'{bar(p * 100, 100, ALERT if detected else NEON)}'
        f'<div style="font-size:.72rem;color:{TXT}">alerts = {evasion_state.get("alerts", 0)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    c1, c2 = st.columns(2)
    c1.metric("Cycle", f'{evasion_state.get("cycle", 0)}/{evasion_state.get("cycles", "?")}')
    c2.metric("Detection", f'{evasion_state.get("detection_rate", 0) * 100:.0f}%')
    c3, c4 = st.columns(2)
    c3.metric("Epsilon", f'{evasion_state.get("epsilon", 0):.3f}')
    c4.metric("Reward", f'{evasion_state.get("reward", 0):+.2f}')
    if detected is not None:
        cls, txt = (("reward-bad", "DETECTED") if detected
                    else ("reward-ok", "EVASION SUCCESS"))
        st.markdown(f'<div class="reward {cls}">{txt}</div>', unsafe_allow_html=True)


def render_run_status(run_state: dict | None) -> None:
    """Détail du dernier événement du pipeline (run_state.json)."""
    st.markdown(
        f'<div class="nz-title">{icon("cpu", 16)} RUN STATE</div>',
        unsafe_allow_html=True,
    )
    if not run_state:
        st.markdown(
            f'<div class="nz-card"><span style="color:{TXT_DIM}">Aucun run.</span></div>',
            unsafe_allow_html=True,
        )
        return
    rows = ""
    for key in ("current_agent", "status", "profile", "duration", "timestamp"):
        if key in run_state:
            rows += (f'<div><span>{key.upper()}</span>'
                     f'<b>{run_state[key]}</b></div>')
    st.markdown(f'<div class="recap">{rows}</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 1 — MISSION CONTROL (briefing en lecture seule)
# ═══════════════════════════════════════════════════════════════════════════
def page_mission_control() -> None:
    run_state = _read_json("run_state.json")
    target = (run_state or {}).get("target", "192.168.100.11")
    profile = (run_state or {}).get("profile", "stealth")

    st.markdown(
        f'<div class="nz-title">{icon("share-2", 16)} TARGET CONFIG</div>',
        unsafe_allow_html=True,
    )
    left, right = st.columns([1, 1.4])
    with left:
        st.text_input("Target IP", target, disabled=True)
        st.text_input("Attacker IP", "192.168.100.10", disabled=True)
        st.text_input("Subnet", "192.168.100.0/24", disabled=True)
    with right:
        st.markdown(network_svg(), unsafe_allow_html=True)

    st.markdown(
        f'<div class="nz-title">{icon("terminal", 16)} LANCER UN RUN (CLI)</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Ce dashboard est un visualiseur : il n'exécute rien. Lance le pipeline "
        "depuis le CLI, l'affichage se met à jour automatiquement."
    )
    st.code(
        "# Pipeline complet\n"
        f"python main.py --target {target} --profile {profile}\n\n"
        "# Boucle d'apprentissage (Q-Learning)\n"
        f"python main.py --target {target} --mode learn --cycles 100\n\n"
        "# Affinage online contre Suricata réel\n"
        f"python main.py --finetune results/qtable_offline.json --target {target} "
        "--eve-log /var/log/suricata/eve.json",
        language="bash",
    )

    st.markdown(
        f'<div class="nz-title">{icon("list", 16)} MISSION BRIEF</div>',
        unsafe_allow_html=True,
    )
    status = (run_state or {}).get("status", "—")
    st.markdown(
        f"""<div class="recap">
        <div><span>TARGET</span><b>{target}</b></div>
        <div><span>PROFILE</span><b>{profile}</b></div>
        <div><span>ÉTAT</span><b>{status}</b></div>
        </div>""",
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 2 — LIVE OPS (visualiseur temps réel)
# ═══════════════════════════════════════════════════════════════════════════
def page_live_operations() -> None:
    run_state = _read_json("run_state.json")
    evasion_state = _read_json("evasion_state.json")
    ptt = _read_json("ptt.json")
    convergence = _read_json("convergence.json", default=[]) or []

    if not run_state and not convergence:
    st.markdown(
            f'<div class="nz-card nz-card-amber">'
            f'<div class="nz-title">{icon("clock", 16, AMBER)} STANDBY</div>'
            f'<span style="color:{TXT}">En attente d\'un run CLI…<br><br>'
            f'Lance : <b>python main.py --target 192.168.100.11 --mode learn</b><br>'
            f'Le dashboard lit results/run_state.json, evasion_state.json, '
            f'ptt.json et convergence.json.</span></div>',
            unsafe_allow_html=True,
        )
        _autorefresh()
        return

    active = (run_state or {}).get("current_agent", "")
    cycle = (evasion_state or {}).get("cycle")

    col_l, col_c, col_r = st.columns([1.2, 2, 1])
    with col_l:
        render_agents(run_state)
        render_ptt(ptt)
    with col_c:
        st.markdown(network_svg(cycle, active), unsafe_allow_html=True)
        render_convergence(convergence)
    with col_r:
        render_evasion(evasion_state)
        render_run_status(run_state)

    _autorefresh()


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

    st.session_state.setdefault("page", "LIVE OPS")
    st.session_state.setdefault("paused_refresh", False)

    run_state = _read_json("run_state.json")
    running = bool(run_state and run_state.get("status") == "running")
    render_status_bar(run_state, running)

    with st.sidebar:
        st.markdown(
            f'<h2 style="color:{NEON};letter-spacing:2px;display:flex;'
            f'align-items:center;gap:8px">{icon("cpu", 22)} NZOYI</h2>',
            unsafe_allow_html=True,
        )
        st.caption(f"v{VERSION} // C2 CONSOLE · VIEWER")
        page = st.radio("Navigation", ["MISSION CONTROL", "LIVE OPS"],
                        index=0 if st.session_state.page == "MISSION CONTROL" else 1)
        st.session_state.page = page

        st.divider()
        if st.button("PAUSE REFRESH" if not st.session_state.paused_refresh else "RESUME REFRESH",
                      width="stretch"):
            st.session_state.paused_refresh = not st.session_state.paused_refresh
            st.rerun()
        if st.button("REFRESH NOW", width="stretch"):
            st.rerun()

        evasion_state = _read_json("evasion_state.json")
        if evasion_state:
            st.markdown(
                f'<div style="text-align:center;font-size:2.4rem;color:{NEON};'
                f'font-weight:700;text-shadow:0 0 12px rgba(0,255,127,.4)">'
                f'{evasion_state.get("cycle", 0)}</div>'
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
