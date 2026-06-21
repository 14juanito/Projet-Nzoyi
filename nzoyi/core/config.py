"""Attack profiles and runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackProfile:
    name: str
    nmap_timing: str
    scan_delay_ms: int
    packet_fragment: bool
    max_parallel: int
    description: str


PROFILES: dict[str, AttackProfile] = {
    "default": AttackProfile(
        name="default",
        nmap_timing="T3",
        scan_delay_ms=0,
        packet_fragment=False,
        max_parallel=10,
        description="Standard scan — high detection risk, fast recon.",
    ),
    "stealth": AttackProfile(
        name="stealth",
        nmap_timing="T2",
        scan_delay_ms=500,
        packet_fragment=True,
        max_parallel=2,
        description="Slow, fragmented scans — lower IDS alert rate.",
    ),
    "aggressive": AttackProfile(
        name="aggressive",
        nmap_timing="T4",
        scan_delay_ms=0,
        packet_fragment=False,
        max_parallel=20,
        description="Fast parallel scanning — baseline comparison.",
    ),
}


def load_profile(name: str) -> AttackProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        available = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile '{name}'. Available: {available}") from exc
