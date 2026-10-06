"""Lecteur du flux d'anomalies AutoZeekWatch (Zeek + KitNET) — analogue à
:class:`nzoyi.tools.ids_log_reader.SuricataLogReader`.

Format de sortie d'AutoZeekWatch (``infer.py``) : chaque log Zeek scoré est
loggé via le module ``logging`` standard, un évènement par ligne, format
``asctime - name - levelname - message`` où ``message`` est
``"<module>: <dict Python>"`` — ``<module>`` est ``conn``/``dns``/``http``/
``ssh``/``ssl`` et ``<dict Python>`` est le ``repr()`` d'un dict contenant
``uid``, ``id.orig_h``, ``id.resp_h``, ``id.orig_p``, ``id.resp_p`` et
``anomaly_score`` (voir ``AutoZeekWatch/infer.py::score_json``). Ce n'est pas
du JSON — c'est un ``repr()`` Python — mais c'est un format structuré,
stable et documenté dans le dépôt amont, donc parsable sans ambiguïté via
``ast.literal_eval``.

Exemple de ligne réelle :
    2026-10-06 10:15:32,041 - root - INFO - conn: {'uid': 'Cabc123', \
'id.resp_h': '192.168.100.13', 'id.orig_h': '192.168.100.10', \
'id.orig_p': 54321, 'id.resp_p': 22, 'anomaly_score': 0.812}

Pas de notion de « bruit décodeur » côté KitNET (pas de règles de signature) :
``security_only`` est accepté pour compatibilité d'interface avec
``SuricataLogReader`` mais n'a aucun effet de filtrage ici.
"""

from __future__ import annotations

import ast
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("nzoyi.tools.zeek_ml_log")

# "2026-10-06 10:15:32,041 - root - INFO - conn: {...}"
_LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})"
    r" - (?P<name>\S+) - (?P<level>\S+) - "
    r"(?P<module>conn|dns|http|ssh|ssl): (?P<payload>\{.*\})\s*$"
)

#: Seuil par défaut si ``config.zeek_ml_threshold`` n'est pas fourni par
#: l'appelant — voir la limite documentée dans le rapport comparatif (J8) :
#: KitNET ne fournit pas de seuil calibré prêt à l'emploi, contrairement au
#: seuil RF (0.41) validé sur le split officiel UNSW-NB15.
DEFAULT_SCORE_THRESHOLD = 1.0


class ZeekMLLogReader:
    """Lit et filtre incrémentalement le flux ``anomalies.log`` d'AutoZeekWatch."""

    def __init__(self, log_path: str, score_threshold: float = DEFAULT_SCORE_THRESHOLD) -> None:
        self.log_path = Path(log_path)
        self.score_threshold = score_threshold
        self._last_position = 0

        if not self.log_path.exists():
            raise FileNotFoundError(f"Zeek+ML anomalies log not found: {log_path}")
        if not self.log_path.is_file():
            raise PermissionError(f"Zeek+ML anomalies path is not a readable file: {log_path}")

    def seek_end(self) -> None:
        """Place le curseur en fin de fichier — ignore l'historique (recon, cycles passés)."""
        try:
            self._last_position = self.log_path.stat().st_size
        except OSError as exc:
            raise PermissionError(f"Cannot stat Zeek+ML log: {self.log_path}") from exc

    def get_recent_alerts(
        self,
        seconds: int = 30,
        source_ip: str | None = None,
        *,
        since_cursor_only: bool = False,
        security_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Lit les anomalies depuis le curseur (incrémental).

        Même contrat que ``SuricataLogReader.get_recent_alerts`` pour que
        :class:`EvaluationAgent` puisse appeler l'une ou l'autre de façon
        interchangeable. ``security_only`` est accepté mais ignoré (pas de
        bruit décodeur à filtrer côté KitNET).
        """
        del security_only  # pas de filtrage de bruit décodeur côté Zeek+ML
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        alerts: list[dict[str, Any]] = []

        try:
            with open(self.log_path, encoding="utf-8") as handle:
                handle.seek(self._last_position)
                for line in handle:
                    parsed = self._parse_line(line)
                    if parsed is None:
                        continue
                    ts, module, payload = parsed

                    if not since_cursor_only:
                        if ts is None or ts < cutoff:
                            continue

                    src_ip = payload.get("id.orig_h", "")
                    if source_ip and src_ip != source_ip:
                        continue

                    score = float(payload.get("anomaly_score", 0.0))
                    if score < self.score_threshold:
                        continue

                    alerts.append(
                        {
                            "signature": f"ZEEK_ML anomaly ({module}, score={score:.4f})",
                            "signature_id": 0,
                            "severity": 0,
                            "category": module,
                            "src_ip": src_ip,
                            "dest_ip": payload.get("id.resp_h", ""),
                            "src_port": payload.get("id.orig_p", 0),
                            "dest_port": payload.get("id.resp_p", 0),
                            "proto": "",
                            "timestamp": ts.isoformat() if ts else "",
                            "anomaly_score": score,
                            "uid": payload.get("uid", ""),
                        }
                    )
                self._last_position = handle.tell()
        except PermissionError as exc:
            raise PermissionError(f"Cannot read Zeek+ML log: {self.log_path}") from exc

        return alerts

    def check_detected(self, seconds: int = 10, source_ip: str | None = None) -> bool:
        return len(self.get_recent_alerts(seconds=seconds, source_ip=source_ip)) > 0

    @classmethod
    def _parse_line(cls, line: str) -> tuple[datetime | None, str, dict[str, Any]] | None:
        match = _LOG_LINE_RE.match(line.strip())
        if not match:
            return None
        try:
            payload = ast.literal_eval(match.group("payload"))
        except (ValueError, SyntaxError):
            logger.debug("Ligne Zeek+ML non parsable (payload invalide): %s", line.strip())
            return None
        if not isinstance(payload, dict):
            return None
        ts = cls._parse_timestamp(match.group("ts"))
        return ts, match.group("module"), payload

    @staticmethod
    def _parse_timestamp(raw: str) -> datetime | None:
        if not raw:
            return None
        try:
            # "YYYY-mm-dd HH:MM:SS,fff" (format par défaut du module logging)
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S,%f")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
