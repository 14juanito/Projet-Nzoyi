"""Agent d'évaluation — fusionne le verdict Suricata (règles) et RF (ML)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.core import config
from nzoyi.llm.evaluation_rationale_llm import EvaluationRationaleLLM
from nzoyi.tools.ids_log_reader import SuricataLogReader
from nzoyi.tools.rf_client import RFClient
from nzoyi.tools.rf_features import features_from_evasion

logger = logging.getLogger("nzoyi.agents.evaluation")


class EvaluationAgent(BaseAgent):
    """Lit Suricata (eve.json) et interroge le détecteur RF, puis fusionne les verdicts."""

    name = "evaluation"

    def __init__(
        self,
        ptt,
        profile,
        attacker_ip: str | None = None,
        use_rf_online: bool = True,
        use_llm: bool = True,
    ) -> None:
        """Si ``use_rf_online`` est False, le client RF n'est pas instancié :
        le signal RF reste neutre (None) en permanence, sans warning, et la
        fusion de détection repose uniquement sur Suricata.

        ``use_llm`` ne contrôle QUE le rationale explicatif ajouté APRÈS le
        calcul de ``detected``/``detection_rate`` (voir :meth:`run`) — ces
        deux champs restent calculés exactement de la même façon, que
        ``use_llm`` soit ``True`` ou ``False``."""
        super().__init__(ptt, profile)
        self.attacker_ip = attacker_ip
        self.use_rf_online = use_rf_online
        self.use_llm = use_llm
        self.rf_client = RFClient(config.rf_endpoint) if use_rf_online else None
        self._total_scans = 0
        self._total_detections = 0
        self._reader: SuricataLogReader | None = None
        self._eve_path: str | None = None

    def _log_raw_response(self, rationale: EvaluationRationaleLLM) -> None:
        """Enregistre dans le PTT le texte brut renvoyé par le backend LLM de
        rationale. N'enregistre rien en l'absence de réponse (LLM désactivé,
        ou backend indisponible). Même séparation de responsabilités qu'en
        J1 : le PTT reste exclusivement la propriété de l'agent."""
        if rationale.last_raw_response is not None:
            self.ptt.add(
                self.name,
                "llm_raw_response_evaluation",
                {"raw": rationale.last_raw_response},
                allow_duplicate=True,
            )

    def baseline_ids(self, eve_log: str | None = None) -> None:
        """Ignore l'historique eve.json (recon, scans précédents) avant les cycles RL.

        Sans ça, chaque évaluation recompte d'anciennes alertes → détection
        artificielle à 100 % même si le cycle courant est furtif.
        """
        eve_log = eve_log or config.eve_log
        if not eve_log or not Path(eve_log).exists():
            return
        try:
            reader = self._get_reader(eve_log)
            reader.seek_end()
            logger.info("Baseline IDS : curseur eve.json placé en fin de fichier.")
        except (FileNotFoundError, PermissionError) as exc:
            logger.warning("Baseline IDS impossible: %s", exc)

    def _get_reader(self, eve_log: str) -> SuricataLogReader:
        if self._reader is None or self._eve_path != eve_log:
            self._reader = SuricataLogReader(eve_log)
            self._eve_path = eve_log
        return self._reader

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
                reader = self._get_reader(eve_log)
                # Curseur persistant : uniquement les alertes *nouvelles* depuis
                # le dernier run / baseline_ids().
                alerts = reader.get_recent_alerts(
                    seconds=30,
                    source_ip=self.attacker_ip,
                    since_cursor_only=True,
                )
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
        if self.rf_client is not None:
            prediction = self.rf_client.predict(self._current_features())
            if prediction is not None:
                rf_proba = prediction["proba"]
                rf_detected = rf_proba >= config.rf_threshold
            else:
                logger.warning(
                    "Endpoint RF injoignable (%s) — signal RF neutre.", config.rf_endpoint
                )

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

        # Couche LLM de RATIONALE EXPLICATIF SEUL (J6) : lecture seule du
        # résultat déjà figé ci-dessus — zéro influence sur detected/
        # detection_rate, qui ne sont plus jamais touchés après ce point.
        rationale_llm = EvaluationRationaleLLM(enabled=self.use_llm)
        result["llm_rationale"] = rationale_llm.decide(result)
        self._log_raw_response(rationale_llm)

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

    def _current_features(self) -> dict[str, Any]:
        """Construit le payload UNSW-NB15 attendu par l'API RF distante."""
        return features_from_evasion(
            self.ptt.get_evasion_strategy(),
            nmap_timing=self.profile.nmap_timing,
            scan_delay_ms=self.profile.scan_delay_ms,
            packet_fragment=self.profile.packet_fragment,
        )
