#!/usr/bin/env bash
# Lance le cockpit Streamlit NZOYI (utilise le venv du projet).
cd "$(dirname "$0")"
if [[ ! -x venv/bin/streamlit ]]; then
  echo "Installation des dépendances…"
  python3 -m venv venv
  ./venv/bin/pip install -r requirements.txt
fi
exec ./venv/bin/streamlit run nzoyi/dashboard/app.py
