"""Agent de reconnaissance — découverte réseau via Nmap."""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.tools.nmap_wrapper import NmapWrapper

logger = logging.getLogger("nzoyi.agents.recon")

_TIMING_MAP: dict[str, int] = {"T2": 2, "T3": 3, "T4": 4}


class ReconAgent(BaseAgent):
    """Scanne la cible avec Nmap (détection de version) et alimente le PTT."""

    name = "recon"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        timing = _TIMING_MAP.get(self.profile.nmap_timing, 3)

        wrapper = NmapWrapper()
        try:
            raw_ports = wrapper.scan(self.ptt.target, scan_type="version", timing=timing)
        except (FileNotFoundError, TimeoutError) as exc:
            logger.warning("Scan Nmap indisponible sur %s: %s", self.ptt.target, exc)
            raw_ports = []

        ports = [
            {
                "host": p.get("host", self.ptt.target),
                "port": p["port"],
                "state": p.get("state", "unknown"),
                "service": p.get("service", ""),
                "product": p.get("product", ""),
                "version": p.get("version", ""),
            }
            for p in raw_ports
            if p.get("state") == "open"
        ]
        open_ports = [p["port"] for p in ports]

        result = {
            "target": self.ptt.target,
            "open_ports": open_ports,
            "ports": ports,
            "scan_type": "version",
            "timing": timing,
            "dry_run": dry_run,
        }
        logger.info("Nmap a trouvé %d ports ouverts sur %s", len(open_ports), self.ptt.target)

        self.ptt.set_recon_results(ports)
        self.ptt.add(self.name, "port_scan", result)
        return result
