"""Passe de rattrapage post-campagne pour les alertes IDS perdues par
latence de lecture (J7-ter, voir docs/evidence/j7-ter/README.md § «
Vérifications complémentaires »).

⚠️ NON FIABLE EN L'ÉTAT — NE PAS UTILISER POUR PRODUIRE DE NOUVEAUX
CHIFFRES SANS AVOIR VÉRIFIÉ LA CONDITION CI-DESSOUS.

Ce module réattribue les alertes par leur horodatage EMBARQUÉ (horloge de
la machine qui a généré l'événement IDS), comparé à des fenêtres de cycle
construites sur l'horloge LOCALE (celle qui a écrit les nœuds PTT). Ces
deux résultats ne sont comparables QUE SI les deux horloges sont
synchronisées — ce qui n'était PAS le cas lors de la campagne J7-ter
originale (poste Kali sans NTP actif, ~38 min de décalage mesurés par
moments, voir docs/evidence/j7-ter/README.md § « Correction majeure »).
Dans ces conditions, ce module a produit de fausses "pertes d'alertes"
pour WhiteRabbitNeo-2-8B/Foundation-Sec-8B-Instruct (chiffres non
confirmés, jamais validés par une méthode fiable) — et aurait tout aussi
bien pu en masquer ou en inventer d'autres.

AVANT toute utilisation : vérifier le décalage d'horloge avec
``run_j7_campaign.check_clock_skew()`` (ajouté précisément pour ça) — un
décalage significatif invalide tout résultat produit ici. Pour un
diagnostic fiable indépendamment de l'horloge, préférer
``nzoyi.agents.evaluation.EvaluationAgent``/``SuricataLogReader.last_debug``
(champ ``eval_debug`` du PTT, positions de curseur/octet — immunisées par
construction à tout décalage d'horloge entre les machines).

Contexte du bug corrigé ICI (en post-traitement, jamais en direct) :
``EvaluationAgent.run()`` lit Suricata puis appelle
``EvaluationRationaleLLM`` (latence 3-95s selon le backend) avant de
rendre la main ; le ``baseline_ids()`` du cycle suivant avance le curseur
du mirror ``eve.json`` juste après. Toute alerte réelle qui arrive sur le
mirror local (relayé par SSH depuis la VM) PENDANT cette fenêtre — après
la lecture du cycle courant, avant le reset du cycle suivant — n'est
jamais comptée par aucun cycle : elle est silencieusement perdue.

Ce module ne touche JAMAIS la boucle live (``EvasionAgent``/
``EvaluationAgent`` en temps réel, récompense Q-learning) — il relit,
après coup, l'intégralité d'un mirror ``eve.json`` déjà enregistré et
réattribue chaque alerte réelle au cycle PTT auquel elle appartient
causalement, par horodatage Suricata (pas par ordre d'arrivée locale).
"""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from nzoyi.tools.ids_log_reader import is_security_alert


def _parse_ts(raw: str) -> datetime:
    cleaned = raw.replace("Z", "+00:00")
    if len(cleaned) >= 5 and cleaned[-5] in "+-" and cleaned[-3] != ":":
        cleaned = f"{cleaned[:-2]}:{cleaned[-2:]}"
    return datetime.fromisoformat(cleaned)


@dataclass
class ReconciledCycle:
    cycle: int
    original_alert_count: int
    original_detected: bool
    corrected_alert_count: int
    corrected_detected: bool
    reattributed_signatures: list[str] = field(default_factory=list)


def load_ids_feedback(ptt_path: Path) -> list[dict[str, Any]]:
    """Charge les nœuds PTT ``ids_feedback``, dans l'ordre d'enregistrement
    (= ordre des cycles, 1 nœud par cycle)."""
    data = json.loads(ptt_path.read_text(encoding="utf-8"))
    nodes = data.get("nodes", data)
    return [n for n in nodes if n.get("kind") == "ids_feedback"]


def load_first_cycle_start(ptt_path: Path) -> datetime | None:
    """Horodatage du tout premier ``evasion_step`` — approxime le moment du
    ``baseline_ids()`` initial (appelé une seule fois avant la boucle de
    cycles, voir ``LearningRunner.run()``), pour borner la fenêtre basse du
    cycle 1.

    SANS cette borne, la fenêtre du cycle 1 serait non bornée vers le passé
    (``lo=None``) et capterait, à tort, tout l'historique du mirror
    ``eve.json`` précédant ce run — y compris le trafic d'un AUTRE backend
    exécuté plus tôt dans la même campagne (le mirror est continu sur toute
    la durée de ``run_j7_campaign.py``, jamais recréé par backend).
    """
    data = json.loads(ptt_path.read_text(encoding="utf-8"))
    nodes = data.get("nodes", data)
    steps = [n for n in nodes if n.get("kind") == "evasion_step" and n.get("timestamp")]
    if not steps:
        return None
    return _parse_ts(steps[0]["timestamp"])


def load_security_alerts(
    mirror_path: Path,
    attacker_ip: str | None = None,
    target_ip: str | None = None,
) -> list[tuple[datetime, str]]:
    """Relit l'INTÉGRALITÉ d'un mirror ``eve.json`` (jamais un curseur
    incrémental ici — c'est tout l'historique qui doit être reconsidéré)
    et renvoie les alertes réelles (hors bruit décodeur, ``is_security_alert``),
    triées par horodatage Suricata."""
    alerts: list[tuple[datetime, str]] = []
    with open(mirror_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            signature = alert.get("signature", "") or ""
            if not is_security_alert(signature):
                continue
            if attacker_ip and event.get("src_ip") != attacker_ip:
                continue
            if target_ip and event.get("dest_ip") != target_ip:
                continue
            ts_raw = event.get("timestamp", "")
            if not ts_raw:
                continue
            try:
                alerts.append((_parse_ts(ts_raw), signature))
            except ValueError:
                continue
    alerts.sort(key=lambda pair: pair[0])
    return alerts


def reconcile(
    ptt_path: Path,
    mirror_path: Path,
    attacker_ip: str | None = None,
    target_ip: str | None = None,
) -> dict[str, Any]:
    """Réattribue chaque alerte réelle du mirror au cycle PTT auquel elle
    appartient causalement, par horodatage — plutôt que par ordre
    d'arrivée locale sur le mirror (ce qui causait la perte).

    La fenêtre du cycle *i* est ``(ids_feedback[i-1].timestamp,
    ids_feedback[i].timestamp]`` (borne basse exclusive, borne haute
    inclusive) : c'est l'intervalle réel pendant lequel ce cycle a émis
    son stimulus et attendu son verdict IDS — qu'une alerte générée dans
    cet intervalle soit arrivée tôt ou tard sur le mirror local ne change
    rien à quel cycle elle appartient. Le cycle 1 est borné par
    :func:`load_first_cycle_start` (premier ``evasion_step``), jamais par
    ``None`` — sinon sa fenêtre capterait tout l'historique du mirror
    précédant ce run, y compris le trafic d'un backend précédent dans la
    même campagne.

    Ne modifie jamais ``rf_detected`` (signal RF, jamais basé sur le
    fichier IDS, donc jamais affecté par ce bug) — seule la composante
    Suricata (``alert_count``/``suricata_detected``) est recalculée, et
    ``detected`` recombiné comme le fait ``EvaluationAgent.run()``
    (``suricata_detected or rf_detected``).
    """
    warnings.warn(
        "ids_reconciliation.reconcile() compare un horodatage EMBARQUÉ "
        "(horloge de la machine qui a généré l'alerte) à des fenêtres "
        "construites sur l'horloge LOCALE (PTT) — résultat invalide si les "
        "deux horloges ne sont pas synchronisées (vérifier au préalable "
        "avec run_j7_campaign.check_clock_skew()). Voir le bandeau "
        "d'avertissement en tête de ce module pour le contexte (J7-ter).",
        stacklevel=2,
    )
    feedback_nodes = load_ids_feedback(ptt_path)
    alerts = load_security_alerts(mirror_path, attacker_ip, target_ip)
    timestamps = [_parse_ts(n["timestamp"]) for n in feedback_nodes]
    first_cycle_start = load_first_cycle_start(ptt_path)

    cycles: list[ReconciledCycle] = []
    reattributed_total = 0

    for i, node in enumerate(feedback_nodes):
        lo = timestamps[i - 1] if i > 0 else first_cycle_start
        hi = timestamps[i]
        in_window = [sig for ts, sig in alerts if (lo is None or ts > lo) and ts <= hi]

        original_count = int(node["data"].get("alert_count") or 0)
        original_detected = bool(node["data"].get("detected"))
        rf_detected = bool(node["data"].get("rf_detected"))

        corrected_count = len(in_window)
        corrected_detected = (corrected_count > 0) or rf_detected

        if corrected_count != original_count:
            reattributed_total += abs(corrected_count - original_count)

        cycles.append(
            ReconciledCycle(
                cycle=i + 1,
                original_alert_count=original_count,
                original_detected=original_detected,
                corrected_alert_count=corrected_count,
                corrected_detected=corrected_detected,
                reattributed_signatures=in_window,
            )
        )

    n = len(cycles)
    original_rate = sum(1 for c in cycles if c.original_detected) / n if n else 0.0
    corrected_rate = sum(1 for c in cycles if c.corrected_detected) / n if n else 0.0

    return {
        "cycles": cycles,
        "n": n,
        "original_detection_rate": original_rate,
        "corrected_detection_rate": corrected_rate,
        "alerts_reattributed": reattributed_total,
    }
