"""Evaluation agent — reads IDS feedback from Suricata eve.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nzoyi.agents.base import BaseAgent


class EvaluationAgent(BaseAgent):
    name = "evaluation"

    def run(self, dry_run: bool = False, eve_log: str | None = None) -> dict[str, Any]:
        alert_count = 0
        source = "simulated"

        if eve_log and Path(eve_log).exists():
            source = eve_log
            with open(eve_log, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event_type") == "alert":
                        alert_count += 1
        elif not dry_run:
            alert_count = 0

        result = {
            "alert_count": alert_count,
            "source": source,
            "dry_run": dry_run,
        }
        self.ptt.add(self.name, "ids_feedback", result)
        return result
