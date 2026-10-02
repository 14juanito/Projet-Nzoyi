"""Construction du vecteur de features UNSW-NB15 pour l'API RF distante.

L'endpoint Flask sur la cible attend les ~42 colonnes numériques/catégorielles
du dataset UNSW-NB15. NZOYI ne dispose que de l'état d'évasion discret
(timing, delay, fragment) : on part d'un flux TCP « de base » puis on module
les champs sensibles (rate, sttl, sload, dur, tailles) selon la stratégie.
"""

from __future__ import annotations

from typing import Any

# Ordre / noms exigés par l'API (réponse d'erreur 400 du service cible).
UNSW_FEATURE_NAMES: tuple[str, ...] = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
    "proto",
    "service",
    "state",
)

_RATE_SCALE = 20.0
_DELAY_SCALE = 100.0
_TIMING_MAP: dict[str, int] = {"T2": 2, "T3": 3, "T4": 4}


def _baseline() -> dict[str, Any]:
    """Flux TCP générique (valeurs neutres, hors stratégie d'évasion)."""
    return {
        "dur": 0.05,
        "spkts": 8,
        "dpkts": 6,
        "sbytes": 512,
        "dbytes": 384,
        "rate": 60.0,
        "sttl": 64,
        "dttl": 64,
        "sload": 200.0,
        "dload": 150.0,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": 0.01,
        "dinpkt": 0.01,
        "sjit": 0.0,
        "djit": 0.0,
        "swin": 255,
        "stcpb": 0,
        "dtcpb": 0,
        "dwin": 255,
        "tcprtt": 0.001,
        "synack": 0.0,
        "ackdat": 0.0,
        "smean": 64,
        "dmean": 64,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 1,
        "ct_state_ttl": 0,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 1,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": 1,
        "ct_srv_dst": 1,
        "is_sm_ips_ports": 0,
        "proto": "tcp",
        "service": "-",
        "state": "FIN",
    }


def features_from_evasion(
    strategy: dict[str, Any] | None = None,
    *,
    nmap_timing: str = "T3",
    scan_delay_ms: int = 0,
    packet_fragment: bool = False,
) -> dict[str, Any]:
    """Construit le payload UNSW-NB15 attendu par ``POST /predict``.

    Args:
        strategy: Entrée PTT ``evasion_strategy`` (clés ``state``, ``action``…).
        nmap_timing / scan_delay_ms / packet_fragment: repli si pas de stratégie.
    """
    feat = _baseline()
    state = (strategy or {}).get("state")
    if state and len(state) >= 3:
        timing, delay_bucket, fragment = int(state[0]), int(state[1]), int(state[2])
    else:
        timing = _TIMING_MAP.get(nmap_timing, 3)
        delay_bucket = min(5, max(0, scan_delay_ms // 100))
        fragment = int(packet_fragment)

    # Cadence / charge : timing bas (T2) → rate plus faible (plus furtif).
    rate = max(0.5, timing * _RATE_SCALE)
    feat["rate"] = float(rate)
    feat["sload"] = float(rate * 40.0)
    feat["dload"] = float(rate * 30.0)
    feat["sttl"] = int(max(32, 72 - timing * 4))

    # Délais inter-paquets / durée : delay_bucket élevé → flux plus lent.
    delay_ms = delay_bucket * _DELAY_SCALE
    feat["dur"] = float(max(0.01, delay_ms / 1000.0 + 0.02))
    feat["sinpkt"] = float(max(0.001, delay_ms / 10000.0))
    feat["dinpkt"] = float(feat["sinpkt"])
    feat["sjit"] = float(delay_bucket * 0.002)

    # Fragmentation → paquets plus petits / plus nombreux.
    if fragment:
        feat["smean"] = 40
        feat["dmean"] = 40
        feat["spkts"] = 16
        feat["dpkts"] = 12
        feat["sbytes"] = int(feat["spkts"] * feat["smean"])
        feat["dbytes"] = int(feat["dpkts"] * feat["dmean"])

    # Garantit la présence de toutes les clés attendues.
    for name in UNSW_FEATURE_NAMES:
        feat.setdefault(name, 0 if name not in ("proto", "service", "state") else "-")
    return {name: feat[name] for name in UNSW_FEATURE_NAMES}
