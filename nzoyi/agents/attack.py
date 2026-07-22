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

    ``target_ports``/``focus_services`` sont fixés par
    :meth:`OrchestratorAgent._apply_plan` (décision stratégique du LLM) : quand
    présents, ils priorisent/filtrent les ports du PTT sans jamais intervenir
    dans la boucle Q-Learning.
    """

    name = "attack"
    target_ports: list[int] | None = None
    focus_services: list[str] | None = None

    def _select_targets(self, open_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filtre par ``focus_services`` puis ordonne selon ``target_ports``."""
        targets = open_ports
        if self.focus_services:
            targets = [
                entry for entry in targets
                if entry.get("service") in self.focus_services
            ]
        if self.target_ports:
            priority = {port: i for i, port in enumerate(self.target_ports)}
            targets = sorted(
                targets, key=lambda entry: priority.get(entry["port"], len(priority))
            )
        return targets

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        open_ports = self._select_targets(self.ptt.get_recon_results())
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
