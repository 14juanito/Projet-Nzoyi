"""Evaluation agent — reads IDS feedback from Suricata eve.json."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.tools.ids_log_reader import SuricataLogReader

logger = logging.getLogger("nzoyi.agents.evaluation")


class EvaluationAgent(BaseAgent):
    name = "evaluation"

    def __init__(self, ptt, profile, attacker_ip: str | None = None) -> None:
        super().__init__(ptt, profile)
        self.attacker_ip = attacker_ip
        self._total_scans = 0
        self._total_detections = 0

    def run(self, dry_run: bool = False, eve_log: str | None = None) -> dict[str, Any]:
        self._total_scans += 1
        alert_count = 0
        signatures: list[str] = []
        source = "simulated"
        detected = False

        if eve_log and Path(eve_log).exists():
            source = eve_log
            try:
                reader = SuricataLogReader(eve_log)
                alerts = reader.get_recent_alerts(seconds=30, source_ip=self.attacker_ip)
                alert_count = len(alerts)
                signatures = [a["signature"] for a in alerts if a.get("signature")]
                detected = alert_count > 0
            except (FileNotFoundError, PermissionError) as exc:
                logger.error("Cannot read EVE log: %s", exc)
                source = f"error: {exc}"
        elif dry_run:
            detected = False
            alert_count = 0
        else:
            detected = False

        if detected:
            self._total_detections += 1

        detection_rate = (
            self._total_detections / self._total_scans if self._total_scans else 0.0
        )

        result = {
            "alert_count": alert_count,
            "detected": detected,
            "detection_rate": detection_rate,
            "signatures": signatures,
            "source": source,
            "dry_run": dry_run,
        }

        self.ptt.record_evaluation(detected, {"alerts": alert_count, "signatures": signatures})
        self.ptt.add(self.name, "ids_feedback", result, allow_duplicate=True)
        return result
