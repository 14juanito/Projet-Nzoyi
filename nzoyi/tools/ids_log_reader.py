"""Suricata EVE JSON log reader with incremental cursor."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("nzoyi.tools.ids_log")

# Événements décodeur / protocole — pas des signatures d'attaque.
# Ex. « SURICATA Ethertype unknown » explose avec nmap -f sur le lab KVM
# et fausse un taux de détection à 100 % sans ET SCAN réel.
_DECODER_NOISE_PREFIXES = (
    "SURICATA Ethertype",
    "SURICATA STREAM",
    "SURICATA TCPv4",
    "SURICATA IPv4",
    "SURICATA ICMPv4",
    "SURICATA UDP",
    "SURICATA Applayer",
)


def is_security_alert(signature: str) -> bool:
    """True si la signature est une règle IDS (ET/GPL/…) plutôt qu'un bruit décodeur."""
    if not signature:
        return False
    upper = signature.upper()
    return not any(upper.startswith(p.upper()) for p in _DECODER_NOISE_PREFIXES)


class SuricataLogReader:
    """Read and filter Suricata eve.json alerts incrementally."""

    def __init__(self, eve_path: str) -> None:
        self.eve_path = Path(eve_path)
        self._last_position = 0

        if not self.eve_path.exists():
            raise FileNotFoundError(f"Suricata EVE log not found: {eve_path}")
        if not self.eve_path.is_file():
            raise PermissionError(f"EVE path is not a readable file: {eve_path}")

    def seek_end(self) -> None:
        """Place le curseur en fin de fichier — ignore l'historique (recon, cycles passés)."""
        try:
            self._last_position = self.eve_path.stat().st_size
        except OSError as exc:
            raise PermissionError(f"Cannot stat EVE log: {self.eve_path}") from exc

    def get_recent_alerts(
        self,
        seconds: int = 30,
        source_ip: str | None = None,
        *,
        since_cursor_only: bool = False,
        security_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Lit les alertes depuis le curseur (incrémental).

        ``since_cursor_only=True`` : ne filtre pas par fenêtre temporelle — utile
        après ``seek_end()`` pour ne compter que les alertes *nouvelles* du cycle.
        ``security_only=True`` : ignore le bruit décodeur (Ethertype unknown, …).
        """
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
                    if not since_cursor_only:
                        if ts is None or ts < cutoff:
                            continue

                    src_ip = event.get("src_ip", "")
                    if source_ip and src_ip != source_ip:
                        continue

                    alert = event.get("alert", {})
                    signature = alert.get("signature", "") or ""
                    if security_only and not is_security_alert(signature):
                        continue

                    alerts.append(
                        {
                            "signature": signature,
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
        cleaned = raw.replace("Z", "+00:00")
        if len(cleaned) >= 5 and cleaned[-5] in "+-" and cleaned[-3] != ":":
            cleaned = f"{cleaned[:-2]}:{cleaned[-2:]}"
        try:
            return datetime.fromisoformat(cleaned)
        except ValueError:
            return None
