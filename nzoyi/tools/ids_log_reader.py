"""Suricata EVE JSON log reader with incremental cursor."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("nzoyi.tools.ids_log")


class SuricataLogReader:
    """Read and filter Suricata eve.json alerts incrementally."""

    def __init__(self, eve_path: str) -> None:
        self.eve_path = Path(eve_path)
        self._last_position = 0

        if not self.eve_path.exists():
            raise FileNotFoundError(f"Suricata EVE log not found: {eve_path}")
        if not self.eve_path.is_file():
            raise PermissionError(f"EVE path is not a readable file: {eve_path}")

    def get_recent_alerts(
        self,
        seconds: int = 30,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        alerts: list[dict[str, Any]] = []

        try:
            with open(self.eve_path, encoding="utf-8") as handle:
                handle.seek(self._last_position)
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

                    ts = self._parse_timestamp(event.get("timestamp", ""))
                    if ts and ts < cutoff:
                        continue

                    src_ip = event.get("src_ip", "")
                    if source_ip and src_ip != source_ip:
                        continue

                    alert = event.get("alert", {})
                    alerts.append(
                        {
                            "signature": alert.get("signature", ""),
                            "signature_id": alert.get("signature_id", 0),
                            "severity": alert.get("severity", 0),
                            "category": alert.get("category", ""),
                            "src_ip": src_ip,
                            "dest_ip": event.get("dest_ip", ""),
                            "src_port": event.get("src_port", 0),
                            "dest_port": event.get("dest_port", 0),
                            "proto": event.get("proto", ""),
                            "timestamp": event.get("timestamp", ""),
                        }
                    )
                self._last_position = handle.tell()
        except PermissionError as exc:
            raise PermissionError(f"Cannot read EVE log: {self.eve_path}") from exc

        return alerts

    def check_detected(self, seconds: int = 10, source_ip: str | None = None) -> bool:
        return len(self.get_recent_alerts(seconds=seconds, source_ip=source_ip)) > 0

    @staticmethod
    def _parse_timestamp(raw: str) -> datetime | None:
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
