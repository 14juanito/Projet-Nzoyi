"""Agent d'attaque — envoie le stimulus réseau vers les ports ouverts du PTT."""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.tools.nmap_wrapper import NmapWrapper

logger = logging.getLogger("nzoyi.agents.attack")

_TIMING_MAP: dict[str, int] = {"T2": 2, "T3": 3, "T4": 4}

# Timeout court pour les scans de la phase d'ATTAQUE (cycles d'évasion). Un
# scan lent (T2, --max-rate 10) qui dépasse ce délai est traité comme une
# attaque NON ABOUTIE, pas comme une erreur fatale. La phase recon garde son
# propre timeout généreux (RECON_TIMEOUT_S) — voir nzoyi/agents/recon.py.
ATTACK_TIMEOUT_S = 30


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
    attack_timeout: int = ATTACK_TIMEOUT_S  # configurable par instance/classe

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
        # Restreint le scan d'attaque aux ports RÉELLEMENT découverts par le
        # recon (présents dans le PTT) pour qu'il tienne dans attack_timeout
        # même en T2, au lieu de balayer la plage par défaut (~1000 ports).
        scan_ports = [entry["port"] for entry in open_ports]

        command_plan = {
            "target": self.ptt.target,
            "scan_type": scan_type,
            "timing": timing,
            "scan_delay_ms": self.profile.scan_delay_ms,
            "fragment": self.profile.packet_fragment,
            "ports": scan_ports,
        }

        executed = False
        timed_out = False
        if dry_run:
            logger.info("Mode plan (dry-run) — commande non exécutée: %s", command_plan)
        elif not open_ports:
            logger.warning("Aucun port ouvert connu (PTT) — aucun stimulus envoyé.")
        else:
            wrapper = NmapWrapper(timeout=self.attack_timeout)
            try:
                wrapper.scan(
                    self.ptt.target,
                    scan_type=scan_type,
                    timing=timing,
                    ports=scan_ports,
                )
                executed = True
            except TimeoutError as exc:
                # Signal, pas erreur fatale : le stimulus n'a pas pu être envoyé
                # dans le temps imparti → attaque NON ABOUTIE, on passe au cycle
                # suivant. La récompense (compute_reward, success=False) pénalise
                # déjà naturellement l'état lent qui a expiré.
                timed_out = True
                logger.warning(
                    "Attaque non aboutie (timeout %ss): %s", self.attack_timeout, exc
                )
            except FileNotFoundError as exc:
                logger.warning("Stimulus d'attaque indisponible: %s", exc)

        attempts: list[dict[str, Any]] = []
        for entry in open_ports:
            attempt = {
                **command_plan,
                "host": entry.get("host", self.ptt.target),
                "port": entry["port"],
                "executed": executed,
                "timed_out": timed_out,
                "dry_run": dry_run,
            }
            attempts.append(attempt)
            self.ptt.record_attack_attempt(attempt)

        result = {
            "attempts": attempts,
            "executed": executed,
            "timed_out": timed_out,
            "dry_run": dry_run,
        }
        self.ptt.add(self.name, "attack_plan", result, allow_duplicate=True)
        return result
