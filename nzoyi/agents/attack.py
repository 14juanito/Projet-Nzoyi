"""Agent d'attaque — envoie le stimulus réseau vers les ports ouverts du PTT."""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.llm.attack_priority_llm import AttackPriorityLLM
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

    def __init__(self, ptt, profile, use_llm: bool = True) -> None:
        super().__init__(ptt, profile)
        self.use_llm = use_llm
        self._last_refined_target_ports: list[int] | None = None

    def _log_raw_response(self, priority: AttackPriorityLLM) -> None:
        """Enregistre dans le PTT le texte brut renvoyé par le backend LLM de
        raffinement. N'enregistre rien en l'absence de réponse (LLM désactivé,
        ou backend indisponible). Même séparation de responsabilités qu'en
        J1 : le PTT reste exclusivement la propriété de l'agent."""
        if priority.last_raw_response is not None:
            self.ptt.add(
                self.name,
                "llm_raw_response_attack",
                {"raw": priority.last_raw_response},
                allow_duplicate=True,
            )

    def _refine_target_priority(self) -> None:
        """Affine ``target_ports`` via :class:`AttackPriorityLLM` — ne touche
        jamais ``target_ports`` si vide/absent (rien à affiner), et ne
        ré-affine pas une valeur déjà affinée (idempotent : la couche
        tactique — ``run`` est aussi appelée à chaque cycle Q-Learning — ne
        doit pas ré-interroger le LLM à chaque cycle pour une sélection de
        cibles qui n'a pas changé depuis la dernière décision stratégique)."""
        if not self.target_ports or self.target_ports == self._last_refined_target_ports:
            return
        vuln_nodes = self.ptt.find(kind="vuln_analysis")
        findings = vuln_nodes[-1].data.get("findings", []) if vuln_nodes else []

        priority = AttackPriorityLLM(enabled=self.use_llm)
        plan = priority.decide(self.target_ports, findings)
        self._log_raw_response(priority)
        self.target_ports = plan["ports_prioritaires"]
        self._last_refined_target_ports = list(self.target_ports)

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
        self._refine_target_priority()
        open_ports = self._select_targets(self.ptt.get_recon_results())
        timing, scan_delay_ms, fragment = self._resolve_scan_params()
        # Toujours -sS pour le stimulus d'attaque : -sV active le NSE
        # (« ET SCAN Nmap Scripting Engine User-Agent ») et fausse l'évasion.
        # La détection de version reste au Recon / Enumerator.
        scan_type = "stealth"
        # Restreint le scan d'attaque aux ports RÉELLEMENT découverts par le
        # recon (présents dans le PTT) pour qu'il tienne dans attack_timeout
        # même en T2, au lieu de balayer la plage par défaut (~1000 ports).
        scan_ports = [entry["port"] for entry in open_ports]

        command_plan = {
            "target": self.ptt.target,
            "scan_type": scan_type,
            "timing": timing,
            "scan_delay_ms": scan_delay_ms,
            "fragment": fragment,
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
                    fragment=fragment,
                    scan_delay_ms=scan_delay_ms,
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
            "timing": timing,
            "scan_delay_ms": scan_delay_ms,
            "fragment": fragment,
        }
        self.ptt.add(self.name, "attack_plan", result, allow_duplicate=True)
        return result

    def _resolve_scan_params(self) -> tuple[int, int, bool]:
        """Applique la stratégie Q-Learning du PTT, sinon le profil CLI."""
        strategy = self.ptt.get_evasion_strategy() or {}
        state = strategy.get("state")
        if state is not None and len(state) >= 3:
            try:
                timing = max(0, min(5, int(state[0])))
                delay_bucket = max(0, min(5, int(state[1])))
                fragment = bool(int(state[2]))
                return timing, delay_bucket * 100, fragment
            except (TypeError, ValueError):
                pass
        timing = _TIMING_MAP.get(self.profile.nmap_timing, 3)
        return timing, int(self.profile.scan_delay_ms), bool(self.profile.packet_fragment)
