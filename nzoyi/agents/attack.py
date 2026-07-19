"""Agent d'attaque — envoie le stimulus réseau vers les ports ouverts du PTT."""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.tools.nmap_wrapper import NmapWrapper

logger = logging.getLogger("nzoyi.agents.attack")

_TIMING_MAP: dict[str, int] = {"T2": 2, "T3": 3, "T4": 4}


class AttackAgent(BaseAgent):
    """Génère un trafic réel vers la cible en appliquant les paramètres d'évasion.

    ``dry_run`` ne fait plus que basculer entre exécution réelle et mode plan :
    la commande est construite mais jamais lancée sur le réseau.
    """

    name = "attack"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        open_ports = self.ptt.get_recon_results()
        timing = _TIMING_MAP.get(self.profile.nmap_timing, 3)
        scan_type = "stealth" if self.profile.packet_fragment else "version"

        command_plan = {
            "target": self.ptt.target,
            "scan_type": scan_type,
            "timing": timing,
            "scan_delay_ms": self.profile.scan_delay_ms,
            "fragment": self.profile.packet_fragment,
        }

        executed = False
        if dry_run:
            logger.info("Mode plan (dry-run) — commande non exécutée: %s", command_plan)
        elif not open_ports:
            logger.warning("Aucun port ouvert connu (PTT) — aucun stimulus envoyé.")
        else:
            wrapper = NmapWrapper()
            try:
                wrapper.scan(self.ptt.target, scan_type=scan_type, timing=timing)
                executed = True
            except (FileNotFoundError, TimeoutError) as exc:
                logger.warning("Stimulus d'attaque indisponible: %s", exc)

        attempts: list[dict[str, Any]] = []
        for entry in open_ports:
            attempt = {
                **command_plan,
                "host": entry.get("host", self.ptt.target),
                "port": entry["port"],
                "executed": executed,
                "dry_run": dry_run,
            }
            attempts.append(attempt)
            self.ptt.record_attack_attempt(attempt)

        result = {"attempts": attempts, "executed": executed, "dry_run": dry_run}
        self.ptt.add(self.name, "attack_plan", result, allow_duplicate=True)
        return result
