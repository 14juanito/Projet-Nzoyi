"""Benchmark multi-modèles pour le composant IDS anomalie (UNSW-NB15).

Ce package étend l'ancien détecteur Random Forest unique en un banc de mesure
comparant 5 familles de classifieurs sur le MÊME espace de features, avec un
seul pipeline de prétraitement partagé et fitté uniquement sur le split
officiel d'entraînement UNSW-NB15. Voir ``benchmark/run_benchmark.py`` pour le
point d'entrée CLI.
"""

from __future__ import annotations
