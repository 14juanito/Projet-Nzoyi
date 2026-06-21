"""NZOYI Streamlit supervision dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

st.set_page_config(page_title="NZOYI Dashboard", page_icon="🐝", layout="wide")

from nzoyi import __version__  # noqa: E402

RESULTS_DIR = Path("results")
AGENTS = [
    "orchestrator", "recon", "enumerator", "vulnerability",
    "evasion", "attack", "evaluation",
]

st.title("🐝 NZOYI Dashboard")
st.caption(f"Multi-Agent IDS Resilience Framework · v{__version__}")

# ── Header ──────────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Version", __version__)
with col2:
  ptt_path = RESULTS_DIR / "ptt.json"
  st.metric("PTT saved", "✓" if ptt_path.exists() else "—")
with col3:
    qtable_path = RESULTS_DIR / "qtable.json"
    st.metric("Q-Table saved", "✓" if qtable_path.exists() else "—")

st.divider()

# ── Agents status ───────────────────────────────────────────────────────────
st.subheader("Agents")
agent_data = []
for agent in AGENTS:
    agent_data.append({
        "Agent": agent,
        "Status": "idle",
        "Last run": "—",
    })
st.dataframe(agent_data, use_container_width=True)

# ── Q-Learning convergence ──────────────────────────────────────────────────
st.subheader("Q-Learning Convergence")
conv_path = RESULTS_DIR / "convergence.json"
if conv_path.exists():
    with open(conv_path, encoding="utf-8") as handle:
        convergence = json.load(handle)
    if convergence:
        chart_data = {
            "cycle": [e["cycle"] for e in convergence],
            "detection_rate": [e["detection_rate"] for e in convergence],
            "epsilon": [e["epsilon"] for e in convergence],
        }
        st.line_chart(chart_data, x="cycle", y=["detection_rate", "epsilon"])
    else:
        st.info("Convergence data is empty. Run: python main.py --mode learn --dry-run")
else:
    st.info("No convergence data yet. Run: python main.py --mode learn --cycles 100 --dry-run")

# ── Pentest Tree ────────────────────────────────────────────────────────────
st.subheader("Pentest Tree (PTT)")
if ptt_path.exists():
    with open(ptt_path, encoding="utf-8") as handle:
        ptt_data = json.load(handle)
    st.json(ptt_data)
else:
    st.info("No PTT snapshot saved. The PTT is populated during pipeline runs.")
