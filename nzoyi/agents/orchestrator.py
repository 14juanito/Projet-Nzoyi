"""Orchestrator agent — coordinates the full pentest pipeline."""

from __future__ import annotations

from typing import Any

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


class OrchestratorAgent(BaseAgent):
    name = "orchestrator"

    def __init__(
        self,
        ptt: PentestTree,
        profile: AttackProfile,
        eve_log: str | None = None,
    ) -> None:
        super().__init__(ptt, profile)
        self.eve_log = eve_log
        learner = EvasionQLearner()
        self.pipeline: list[BaseAgent] = [
            ReconAgent(ptt, profile),
            EnumeratorAgent(ptt, profile),
            VulnerabilityAgent(ptt, profile),
            EvasionAgent(ptt, profile, learner=learner),
            AttackAgent(ptt, profile),
            EvaluationAgent(ptt, profile),
        ]

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for agent in self.pipeline:
            if isinstance(agent, EvaluationAgent):
                results[agent.name] = agent.run(dry_run=dry_run, eve_log=self.eve_log)
            else:
                results[agent.name] = agent.run(dry_run=dry_run)

        summary = self.ptt.summary()
        self.ptt.add(self.name, "pipeline_complete", summary)
        return {"agents": results, "ptt": self.ptt.summary()}
