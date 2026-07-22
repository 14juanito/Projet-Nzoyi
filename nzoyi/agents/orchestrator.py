"""Agent orchestrateur — coordonne le pipeline complet de pentest."""

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
from nzoyi.core.config import AttackProfile, load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.llm.orchestrator_llm import LLMOrchestrator
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
        use_llm: bool = True,
        use_rf_online: bool = True,
    ) -> None:
        super().__init__(ptt, profile)
        self.eve_log = eve_log
        self.attacker_ip = attacker_ip
        self.on_agent_status = on_agent_status
        self.use_llm = use_llm
        self.current_plan: dict[str, Any] = {}
        self.learner = EvasionQLearner()
        self.evasion = EvasionAgent(ptt, profile, learner=self.learner)
        self.evaluation = EvaluationAgent(
            ptt, profile, attacker_ip=attacker_ip, use_rf_online=use_rf_online
        )
        self.recon = ReconAgent(ptt, profile)
        self.enumerator = EnumeratorAgent(ptt, profile)
        self.vulnerability = VulnerabilityAgent(ptt, profile)
        self.attack = AttackAgent(ptt, profile)
        # Ordered agent list consumed by the interactive runners (nzoyi.ui).
        self.pipeline: list[BaseAgent] = [
            self.recon,
            self.enumerator,
            self.vulnerability,
            self.evasion,
            self.attack,
            self.evaluation,
        ]

    def _status(self, name: str, status: str, detail: str = "") -> None:
        if self.on_agent_status:
            self.on_agent_status(name, status, detail)

    def _apply_profile(self, profile: AttackProfile) -> None:
        """Propagate a (possibly new) profile to the orchestrator and agents."""
        self.profile = profile
        for agent in self.pipeline:
            agent.profile = profile

    def _apply_plan(self, plan: dict[str, Any]) -> None:
        """Fait exécuter par le pipeline la décision stratégique du LLM.

        Ordonne les cibles d'attaque selon ``ports_cibles`` et transmet ce
        classement, ainsi que ``services_focus``, à :class:`AttackAgent` via
        les attributs ``target_ports``/``focus_services`` — c'est
        :meth:`AttackAgent.run` qui applique concrètement ce filtrage/tri.
        """
        self.attack.target_ports = list(plan.get("ports_cibles", []))
        self.attack.focus_services = list(plan.get("services_focus", []))

    def _strategic_plan(self) -> dict[str, Any]:
        """Exécute la couche stratégique LLM UNE fois (jamais dans la boucle RL).

        Appelle :class:`LLMOrchestrator` pour choisir le profil d'attaque et les
        ports prioritaires, applique le profil choisi à tous les agents, et
        enregistre la décision dans le PTT. Utilise le repli déterministe quand
        ``use_llm`` est ``False`` ou qu'aucune clé API n'est disponible.
        """
        planner = LLMOrchestrator(enabled=self.use_llm)
        plan = planner.decide(self.ptt.summary())
        try:
            self._apply_profile(load_profile(plan["profil"]))
        except (KeyError, ValueError) as exc:
            logger.warning("Profil LLM invalide (%s) — profil courant conservé.", exc)
        self.current_plan = plan
        self.ptt.add(self.name, "llm_strategy", plan, allow_duplicate=True)
        return plan

    def _strategic_replan(self) -> dict[str, Any]:
        """Ré-évalue la stratégie UNE seule fois, avec le PTT enrichi par recon/enum/vuln.

        Ne doit jamais être appelée à l'intérieur de la boucle Q-Learning : la
        couche stratégique (LLM) reste distincte de la couche tactique (RL).
        """
        planner = LLMOrchestrator(enabled=self.use_llm)
        plan = planner.decide(self.ptt.summary())
        try:
            self._apply_profile(load_profile(plan["profil"]))
        except (KeyError, ValueError) as exc:
            logger.warning("Profil LLM invalide en replan (%s) — profil courant conservé.", exc)
        self.current_plan = plan
        self.ptt.add(self.name, "llm_replan", plan, allow_duplicate=True)
        return plan

    def _run_agents(
        self, results: dict[str, Any], steps: list[tuple[str, BaseAgent, dict[str, Any]]]
    ) -> None:
        for name, agent, kwargs in steps:
            self._status(name, "running")
            try:
                results[name] = agent.run(**kwargs)
                detail = str(results[name].get("open_ports", results[name].get("alert_count", "")))
                self._status(name, "done", detail)
            except Exception as exc:
                self._status(name, "error", str(exc))
                raise

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        self._strategic_plan()
        results: dict[str, Any] = {}

        self._run_agents(results, [
            ("recon", self.recon, {"dry_run": dry_run}),
            ("enumerator", self.enumerator, {"dry_run": dry_run}),
            ("vulnerability", self.vulnerability, {"dry_run": dry_run}),
        ])

        plan = self._strategic_replan()
        self.ptt.add(self.name, "llm_decision", plan, allow_duplicate=True)

        if not plan["lancer_boucle_evasion"]:
            logger.info("Boucle d'évasion avortée: %s", plan["raison"])
            self.ptt.add(self.name, "evasion_aborted", plan)
        else:
            self._apply_plan(plan)
            self._run_agents(results, [
                ("evasion", self.evasion, {"dry_run": dry_run}),
                ("attack", self.attack, {"dry_run": dry_run}),
                ("evaluation", self.evaluation, {"dry_run": dry_run, "eve_log": self.eve_log}),
            ])

        self.ptt.add(self.name, "pipeline_complete", self.ptt.summary())
        return {"agents": results, "ptt": self.ptt.summary()}

    def learning_loop(self, cycles: int | None = None, dry_run: bool = True) -> dict[str, Any]:
        """Exécute recon/enum/vuln puis la boucle évasion → attaque → évaluation → apprentissage.

        ``cycles`` prime sur la décision du LLM quand il est fourni ; sinon le
        nombre de cycles vient de ``plan["cycles"]`` (couche stratégique).
        """
        self._strategic_plan()
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

        plan = self._strategic_replan()
        self.ptt.add(self.name, "llm_decision", plan, allow_duplicate=True)

        if not plan["lancer_boucle_evasion"]:
            logger.info("Boucle d'évasion avortée: %s", plan["raison"])
            self.ptt.add(self.name, "evasion_aborted", plan)
            results_dir = Path("results")
            results_dir.mkdir(exist_ok=True)
            self.learner.save(results_dir / "qtable.json")
            with open(results_dir / "convergence.json", "w", encoding="utf-8") as handle:
                json.dump(convergence, handle, indent=2)
            self.ptt.add(self.name, "learning_complete", {
                "cycles": 0,
                "final_detection_rate": 0,
                "final_epsilon": self.learner.epsilon,
            })
            return {
                "cycles": 0,
                "convergence": convergence,
                "final_detection_rate": 0,
                "qtable_path": str(results_dir / "qtable.json"),
                "convergence_path": str(results_dir / "convergence.json"),
            }

        self._apply_plan(plan)
        if cycles is None:
            cycles = plan["cycles"]

        for cycle in range(1, cycles + 1):
            self._status("evasion", "running", f"cycle {cycle}/{cycles}")
            evasion_result = self.evasion.run(dry_run=dry_run)
            self.attack.run(dry_run=dry_run)
            eval_result = self.evaluation.run(
                dry_run=dry_run, eve_log=self.eve_log
            )
            detected = eval_result.get("detected", False)
            learn_result = self.evasion.learn(detected, p_detect=eval_result.get("rf_proba"))

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

    @staticmethod
    def _offline_final_detection_rate() -> float | None:
        """Read the final offline detection rate from convergence_offline.json."""
        path = Path("results") / "convergence_offline.json"
        if not path.is_file():
            return None
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        if not data:
            return None
        return float(data[-1].get("detection_rate", 0.0))

    def finetune_online(
        self,
        warm_qtable: str,
        cycles: int = 50,
        epsilon: float = 0.05,
        alert_threshold: int = 3,
    ) -> dict[str, Any]:
        """Fine-tune an offline-trained Q-table against a real Suricata IDS.

        Warm-starts the learner from ``warm_qtable`` with a low exploration
        rate, then runs the tactical loop reading REAL detection feedback from
        ``self.evaluation.run(eve_log=...)`` (Suricata eve.json) instead of the
        simulation. The strategic LLM layer runs once beforehand.

        Args:
            warm_qtable: Path to the offline Q-table (JSON) to warm-start from.
            cycles: Number of online fine-tuning cycles.
            epsilon: Forced (low) exploration rate for online refinement.
            alert_threshold: Alert count mapped to ``p_detect == 1.0``;
                ``p_detect = min(1.0, alert_count / alert_threshold)``.

        Returns:
            A dict with convergence data, output paths and the sim-to-real gap
            (online final detection rate minus offline final detection rate).
        """
        self._strategic_plan()

        learner = EvasionQLearner.load(warm_qtable)
        learner.epsilon = epsilon
        learner.epsilon_min = min(learner.epsilon_min, epsilon)
        self.learner = learner
        self.evasion.learner = learner

        for name, agent, kwargs in [
            ("recon", self.recon, {"dry_run": False}),
            ("enumerator", self.enumerator, {"dry_run": False}),
            ("vulnerability", self.vulnerability, {"dry_run": False}),
        ]:
            self._status(name, "running")
            agent.run(**kwargs)
            self._status(name, "done")

        convergence: list[dict[str, Any]] = []
        detections = 0

        for cycle in range(1, cycles + 1):
            self._status("evasion", "running", f"cycle {cycle}/{cycles}")
            self.evasion.run(dry_run=False)
            self.attack.run(dry_run=False)
            eval_result = self.evaluation.run(dry_run=False, eve_log=self.eve_log)

            alert_count = int(eval_result.get("alert_count", 0))
            detected = bool(eval_result.get("detected", alert_count > 0))
            p_detect = min(1.0, alert_count / alert_threshold) if alert_threshold else float(detected)

            learn_result = self.evasion.learn(detected, p_detect=p_detect)

            if detected:
                detections += 1
            detection_rate = detections / cycle

            convergence.append({
                "cycle": cycle,
                "detected": detected,
                "alert_count": alert_count,
                "p_detect": round(p_detect, 4),
                "reward": round(learn_result["reward"], 4),
                "epsilon": round(learn_result["epsilon"], 4),
                "detection_rate": round(detection_rate, 4),
            })

            if cycle % 10 == 0:
                logger.info(
                    "Online cycle %d/%d — detection_rate=%.2f epsilon=%.4f",
                    cycle, cycles, detection_rate, learn_result["epsilon"],
                )

        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        self.learner.save(results_dir / "qtable_online.json")
        with open(results_dir / "convergence_online.json", "w", encoding="utf-8") as handle:
            json.dump(convergence, handle, indent=2)

        online_final = convergence[-1]["detection_rate"] if convergence else 0.0
        offline_final = self._offline_final_detection_rate()
        sim_to_real_gap = (
            round(online_final - offline_final, 4)
            if offline_final is not None
            else None
        )

        self.ptt.add(self.name, "finetune_complete", {
            "cycles": cycles,
            "online_final_detection_rate": online_final,
            "offline_final_detection_rate": offline_final,
            "sim_to_real_gap": sim_to_real_gap,
        })

        return {
            "cycles": cycles,
            "convergence": convergence,
            "online_final_detection_rate": online_final,
            "offline_final_detection_rate": offline_final,
            "sim_to_real_gap": sim_to_real_gap,
            "qtable_path": str(results_dir / "qtable_online.json"),
            "convergence_path": str(results_dir / "convergence_online.json"),
        }
