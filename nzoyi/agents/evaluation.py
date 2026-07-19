"""Agent d'évaluation — fusionne le verdict Suricata (règles) et RF (ML)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.core import config
from nzoyi.tools.ids_log_reader import SuricataLogReader
from nzoyi.tools.rf_client import RFClient

logger = logging.getLogger("nzoyi.agents.evaluation")

_TIMING_MAP: dict[str, int] = {"T2": 2, "T3": 3, "T4": 4}
_RATE_SCALE = 20.0
_DELAY_SCALE = 100.0


class EvaluationAgent(BaseAgent):
    """Lit Suricata (eve.json) et interroge le détecteur RF, puis fusionne les verdicts."""

    name = "evaluation"

    def __init__(self, ptt, profile, attacker_ip: str | None = None) -> None:
        super().__init__(ptt, profile)
        self.attacker_ip = attacker_ip
        self.rf_client = RFClient(config.rf_endpoint)
        self._total_scans = 0
        self._total_detections = 0

    def run(self, dry_run: bool = False, eve_log: str | None = None) -> dict[str, Any]:
        self._total_scans += 1
        eve_log = eve_log or config.eve_log

        alert_count = 0
        signatures: list[str] = []
        suricata_detected = False
        source = "unavailable"

        if eve_log and Path(eve_log).exists():
            source = eve_log
            try:
                reader = SuricataLogReader(eve_log)
                alerts = reader.get_recent_alerts(seconds=30, source_ip=self.attacker_ip)
                alert_count = len(alerts)
                signatures = [a["signature"] for a in alerts if a.get("signature")]
                suricata_detected = alert_count > 0
            except (FileNotFoundError, PermissionError) as exc:
                logger.warning("Lecture du log Suricata impossible: %s", exc)
                source = "unavailable"
        else:
            logger.warning("Log Suricata introuvable (%s) — signal Suricata neutre.", eve_log)

        rf_proba = 0.0
        rf_detected = False
        prediction = self.rf_client.predict(self._current_features())
        if prediction is not None:
            rf_proba = prediction["proba"]
            rf_detected = rf_proba >= config.rf_threshold
        else:
            logger.warning("Endpoint RF injoignable (%s) — signal RF neutre.", config.rf_endpoint)

        detected = suricata_detected or rf_detected
        if detected:
            self._total_detections += 1
        detection_rate = (
            self._total_detections / self._total_scans if self._total_scans else 0.0
        )

        result = {
            "detected": detected,
            "suricata_detected": suricata_detected,
            "rf_detected": rf_detected,
            "rf_proba": rf_proba,
            "alert_count": alert_count,
            "signatures": signatures,
            "detection_rate": detection_rate,
            "source": source,
            "dry_run": dry_run,
        }

        self.ptt.record_evaluation(
            detected,
            {
                "suricata_detected": suricata_detected,
                "rf_detected": rf_detected,
                "rf_proba": rf_proba,
                "alert_count": alert_count,
                "signatures": signatures,
            },
        )
        self.ptt.add(self.name, "ids_feedback", result, allow_duplicate=True)
        return result

    def _current_features(self) -> dict[str, float]:
        """Dérive le vecteur de features RF de la stratégie d'évasion courante (PTT)."""
        strategy = self.ptt.get_evasion_strategy()
        state = strategy.get("state")
        if state:
            timing, delay_bucket, fragment = state
        else:
            timing = _TIMING_MAP.get(self.profile.nmap_timing, 3)
            delay_bucket = min(5, self.profile.scan_delay_ms // 100)
            fragment = int(self.profile.packet_fragment)
        return {
            "rate": timing * _RATE_SCALE,
            "delay": delay_bucket * _DELAY_SCALE,
            "frag": float(fragment),
        }
