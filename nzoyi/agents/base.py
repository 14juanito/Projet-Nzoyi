"""Base class for all NZOYI agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from nzoyi.core.config import AttackProfile
from nzoyi.core.ptt import PentestTree


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, ptt: PentestTree, profile: AttackProfile) -> None:
        self.ptt = ptt
        self.profile = profile

    @abstractmethod
    def run(self, dry_run: bool = False) -> dict[str, Any]:
        """Execute the agent's task and record results in the PTT."""
