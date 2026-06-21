"""Orchestrator agent — coordinates the full pentest pipeline."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from nzoyi.agents.attack import AttackAgent
from nzoyi.agents.base import BaseAgent
from nzoyi.agents.enumerator import EnumeratorAgent
from nzoyi.agents.evaluation import EvaluationAgent
from nzoyi.agents.evasion import EvasionAgent
from nzoyi.agents.recon import ReconAgent
from nzoyi.agents.vulnerability import VulnerabilityAgent
from nzoyi.core.config import AttackProfile
from nzoyi.core.ptt import PentestTree
from nzoyi.rl.qlearning import EvasionQLearner

logger = logging.getLogger("nzoyi.agents.orchestrator")


class OrchestratorAgent(BaseAgent):
    name = "orchestrator"

    def __init__(
        self,
        ptt: PentestTree,
        profile: AttackProfile,
        eve_log: str | None = None,
        attacker_ip: str | None = None,
        on_agent_status: Callable[[str, str, str], None] | None = None,
    ) -> None:
        super().__init__(ptt, profile)
        self.eve_log = eve_log
        self.attacker_ip = attacker_ip
        self.on_agent_status = on_agent_status
        self.learner = EvasionQLearner()
        self.evasion = EvasionAgent(ptt, profile, learner=self.learner)
        self.evaluation = EvaluationAgent(ptt, profile, attacker_ip=attacker_ip)
        self.recon = ReconAgent(ptt, profile)
        self.enumerator = EnumeratorAgent(ptt, profile)
        self.vulnerability = VulnerabilityAgent(ptt, profile)
        self.attack = AttackAgent(ptt, profile)

    def _status(self, name: str, status: str, detail: str = "") -> None:
        if self.on_agent_status:
            self.on_agent_status(name, status, detail)

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        results: dict[str, Any] = {}
        pipeline: list[tuple[str, BaseAgent, dict[str, Any]]] = [
            ("recon", self.recon, {"dry_run": dry_run}),
            ("enumerator", self.enumerator, {"dry_run": dry_run}),
            ("vulnerability", self.vulnerability, {"dry_run": dry_run}),
            ("evasion", self.evasion, {"dry_run": dry_run}),
            ("attack", self.attack, {"dry_run": dry_run}),
            ("evaluation", self.evaluation, {"dry_run": dry_run, "eve_log": self.eve_log}),
        ]

        for name, agent, kwargs in pipeline:
            self._status(name, "running")
            try:
                results[name] = agent.run(**kwargs)
                detail = str(results[name].get("open_ports", results[name].get("alert_count", "")))
                self._status(name, "done", detail)
            except Exception as exc:
                self._status(name, "error", str(exc))
                raise

        self.ptt.add(self.name, "pipeline_complete", self.ptt.summary())
        return {"agents": results, "ptt": self.ptt.summary()}

    def learning_loop(self, cycles: int = 100, dry_run: bool = True) -> dict[str, Any]:
        """Run recon pipeline then iterative evasion → attack → evaluation → learn."""
        convergence: list[dict[str, Any]] = []
        detections = 0

        for name, agent, kwargs in [
            ("recon", self.recon, {"dry_run": dry_run}),
            ("enumerator", self.enumerator, {"dry_run": dry_run}),
            ("vulnerability", self.vulnerability, {"dry_run": dry_run}),
        ]:
            self._status(name, "running")
            agent.run(**kwargs)
            self._status(name, "done")

        for cycle in range(1, cycles + 1):
            self._status("evasion", "running", f"cycle {cycle}/{cycles}")
            evasion_result = self.evasion.run(dry_run=dry_run)
            self.attack.run(dry_run=dry_run)
            eval_result = self.evaluation.run(
                dry_run=dry_run, eve_log=self.eve_log
            )
            detected = eval_result.get("detected", False)
            learn_result = self.evasion.learn(detected)

            if detected:
                detections += 1
            detection_rate = detections / cycle

            entry = {
                "cycle": cycle,
                "detected": detected,
                "reward": learn_result["reward"],
                "epsilon": learn_result["epsilon"],
                "detection_rate": round(detection_rate, 4),
            }
            convergence.append(entry)

            if cycle % 10 == 0:
                logger.info(
                    "Cycle %d/%d — detection_rate=%.2f epsilon=%.4f",
                    cycle, cycles, detection_rate, learn_result["epsilon"],
                )
                self._status("evasion", "done", f"rate={detection_rate:.2f}")

        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        self.learner.save(results_dir / "qtable.json")
        with open(results_dir / "convergence.json", "w", encoding="utf-8") as handle:
            json.dump(convergence, handle, indent=2)

        self.ptt.add(self.name, "learning_complete", {
            "cycles": cycles,
            "final_detection_rate": convergence[-1]["detection_rate"] if convergence else 0,
            "final_epsilon": convergence[-1]["epsilon"] if convergence else 0,
        })

        return {
            "cycles": cycles,
            "convergence": convergence,
            "final_detection_rate": convergence[-1]["detection_rate"] if convergence else 0,
            "qtable_path": str(results_dir / "qtable.json"),
            "convergence_path": str(results_dir / "convergence.json"),
        }
