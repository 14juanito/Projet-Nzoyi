"""Reconnaissance agent — network discovery via Nmap."""

from __future__ import annotations

import logging
from typing import Any

from nzoyi.agents.base import BaseAgent
from nzoyi.tools.nmap_wrapper import NmapWrapper

logger = logging.getLogger("nzoyi.agents.recon")

PROFILE_SCAN: dict[str, tuple[str, int]] = {
    "stealth": ("stealth", 2),
    "default": ("version", 3),
    "aggressive": ("version", 4),
}

SIMULATED_PORTS = [22, 80, 443, 21]


class ReconAgent(BaseAgent):
    name = "recon"

    def run(self, dry_run: bool = False) -> dict[str, Any]:
        scan_type, timing = PROFILE_SCAN.get(
            self.profile.name, ("version", 3)
        )

        if dry_run:
            ports = [
                {"host": self.ptt.target, "port": p, "state": "open", "service": ""}
                for p in SIMULATED_PORTS
            ]
            result = {
                "target": self.ptt.target,
                "open_ports": SIMULATED_PORTS,
                "ports": ports,
                "scan_type": scan_type,
                "timing": timing,
                "dry_run": True,
            }
        else:
            wrapper = NmapWrapper()
            ports = wrapper.scan(self.ptt.target, scan_type=scan_type, timing=timing)
            open_ports = [p["port"] for p in ports if p.get("state") == "open"]
            result = {
                "target": self.ptt.target,
                "open_ports": open_ports,
                "ports": ports,
                "scan_type": scan_type,
                "timing": timing,
                "dry_run": False,
            }
            logger.info("Nmap found %d open ports on %s", len(open_ports), self.ptt.target)

        self.ptt.set_recon_results(result["ports"])
        self.ptt.add(self.name, "port_scan", result)
        return result
