"""Nmap wrapper — python-nmap or CLI fallback with XML parsing."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any

logger = logging.getLogger("nzoyi.tools.nmap")

SCAN_FLAGS: dict[str, list[str]] = {
    "basic": ["-sT"],
    "version": ["-sV"],
    "stealth": ["-sS", "--max-rate", "10"],
}


class NmapWrapper:
    """Unified interface for Nmap scanning."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        self._use_python_nmap = False
        try:
            import nmap  # noqa: F401

            self._use_python_nmap = True
        except ImportError:
            if not shutil.which("nmap"):
                logger.warning("nmap not found — scans will fail outside dry-run")

    def scan(
        self,
        target: str,
        scan_type: str = "version",
        timing: int = 3,
    ) -> list[dict[str, Any]]:
        flags = SCAN_FLAGS.get(scan_type, SCAN_FLAGS["version"])
        timing = max(0, min(5, timing))

        if self._use_python_nmap:
            return self._scan_python_nmap(target, flags, timing)
        return self._scan_cli(target, flags, timing)

    def _scan_python_nmap(
        self, target: str, flags: list[str], timing: int
    ) -> list[dict[str, Any]]:
        import nmap

        scanner = nmap.PortScanner()
        args = " ".join(flags) + f" -T{timing}"
        scanner.scan(hosts=target, arguments=args)
        return self._parse_python_nmap(scanner, target)

    def _scan_cli(
        self, target: str, flags: list[str], timing: int
    ) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            raise FileNotFoundError(
                "nmap is not installed. Install with: sudo apt install nmap"
            )

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = [
            "nmap",
            *flags,
            f"-T{timing}",
            "-oX",
            xml_path,
            target,
        ]
        logger.info("Running: %s", " ".join(cmd))
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Nmap scan timed out after {self.timeout}s") from exc

        return parse_nmap_xml(xml_path)

    def _parse_python_nmap(self, scanner, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        host_data = scanner.all_hosts()
        if not host_data:
            return results

        host = host_data[0]
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                info = scanner[host][proto][port]
                results.append(
                    {
                        "host": host,
                        "port": port,
                        "state": info.get("state", "unknown"),
                        "service": info.get("name", ""),
                        "protocol": proto,
                        "version": info.get("version", ""),
                        "product": info.get("product", ""),
                    }
                )
        return results


def parse_nmap_xml(xml_path: str) -> list[dict[str, Any]]:
    """Parse Nmap XML output into a list of port dicts."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results: list[dict[str, Any]] = []

    for host in root.findall("host"):
        addr = host.find("address")
        host_ip = addr.get("addr", "") if addr is not None else ""

        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            results.append(
                {
                    "host": host_ip,
                    "port": port_id,
                    "state": "open",
                    "service": service,
                    "protocol": proto,
                    "version": version,
                    "product": product,
                }
            )
    return results
