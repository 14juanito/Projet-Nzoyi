"""
NZOYI — Terminal UI and visual styling.
Provides the ASCII banner, colored output, and formatted logging.
"""

from __future__ import annotations

import logging
import re
import sys
from datetime import datetime
from typing import Any


# ── ANSI color codes ─────────────────────────────────────────

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Nzoyi palette : amber/gold (wasp theme)
    GOLD = "\033[38;5;220m"
    AMBER = "\033[38;5;214m"
    ORANGE = "\033[38;5;208m"
    DARK = "\033[38;5;94m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    GREEN = "\033[38;5;114m"
    RED = "\033[38;5;196m"
    CYAN = "\033[38;5;81m"
    YELLOW = "\033[38;5;228m"

    BG_DARK = "\033[48;5;233m"

    @staticmethod
    def strip() -> bool:
        """Disable colors if not a real terminal."""
        return not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty()


def c(text: str, color: str) -> str:
    """Colorize text. Falls back to plain text if no TTY."""
    if Color.strip():
        return text
    return f"{color}{text}{Color.RESET}"


# ── ASCII Art Banner ─────────────────────────────────────────

BANNER = r"""
{gold}███╗   ██╗{amber}███████╗{orange} ██████╗ {gold}██╗   ██╗{amber}██╗{reset}
{gold}████╗  ██║{amber}╚══███╔╝{orange}██╔═══██╗{gold}╚██╗ ██╔╝{amber}██║{reset}
{gold}██╔██╗ ██║{amber}  ███╔╝ {orange}██║   ██║{gold} ╚████╔╝ {amber}██║{reset}
{gold}██║╚██╗██║{amber} ███╔╝  {orange}██║   ██║{gold}  ╚██╔╝  {amber}██║{reset}
{gold}██║ ╚████║{amber}███████╗{orange}╚██████╔╝{gold}   ██║   {amber}██║{reset}
{gold}╚═╝  ╚═══╝{amber}╚══════╝{orange} ╚═════╝ {gold}   ╚═╝   {amber}╚═╝{reset}
"""

BOX_TOP = "╭─────────────────────────────────────────────────────────────╮"
BOX_MID = "├─────────────────────────────────────────────────────────────┤"
BOX_BOT = "╰─────────────────────────────────────────────────────────────╯"
BOX_W = 61  # inner width


def _pad(text: str, width: int = BOX_W - 4) -> str:
    """Pad text to fixed width inside box, accounting for ANSI codes."""
    clean = re.sub(r"\033\[[0-9;]*m", "", text)
    padding = max(0, width - len(clean))
    return text + " " * padding


def print_banner(version: str = "0.1.0") -> None:
    """Print the full NZOYI startup banner."""
    if Color.strip():
        formatted = BANNER.format(gold="", amber="", orange="", reset="")
    else:
        formatted = BANNER.format(
            gold=Color.GOLD, amber=Color.AMBER, orange=Color.ORANGE, reset=Color.RESET
        )

    print(formatted)

    g, a, o, w, d, rst = (
        Color.GOLD, Color.AMBER, Color.ORANGE, Color.WHITE, Color.DIM, Color.RESET,
    )
    gn, cy, rd = Color.GREEN, Color.CYAN, Color.RED

    if Color.strip():
        g = a = o = w = d = rst = gn = cy = rd = ""

    inner = len(BOX_TOP) - 2  # largeur utile entre les bordures │ │

    def _row(marker: str, marker_col: str, text: str, text_col: str) -> str:
        """Construit une ligne alignee ; le padding se calcule sur le texte brut."""
        plain = f"  {marker}  {text}"
        pad = " " * max(0, inner - len(plain))
        return (
            f"  {a}│{rst}  {marker_col}{marker}{rst}  "
            f"{text_col}{text}{rst}{pad}{a}│{rst}"
        )

    print(f"  {a}{BOX_TOP}{rst}")
    print(_row("", "", f"NZOYI v{version} · Multi-Agent IDS Resilience Framework", g))
    print(f"  {a}{BOX_MID}{rst}")
    print(_row("[>]", cy, "Adaptive Q-Learning Evasion Engine", w))
    print(_row("[#]", gn, "Defensive Research · IDS Robustness Testing", w))
    print(_row("[~]", o, "Cybernetic Feedback Loop · 7 Autonomous Agents", w))
    print(f"  {a}{BOX_BOT}{rst}")
    print()


def print_config_box(
    target: str,
    profile: str,
    mode: str = "pipeline",
    cycles: int | None = None,
    eve_log: str | None = None,
) -> None:
    """Print a styled configuration summary box."""
    g, a, w, d, gn, cy, rst = (
        Color.GOLD, Color.AMBER, Color.WHITE, Color.DIM,
        Color.GREEN, Color.CYAN, Color.RESET,
    )
    if Color.strip():
        g = a = w = d = gn = cy = rst = ""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  {d}{'─' * 61}{rst}")

    entries = [
        ("🎯 Target", target),
        ("⚙️  Profile", profile),
        ("📋 Mode", mode),
    ]
    if cycles is not None:
        entries.append(("🔄 Cycles", str(cycles)))
    if eve_log:
        entries.append(("📊 EVE Log", eve_log))
    entries.append(("🕐 Started", now))

    for icon_label, value in entries:
        print(f"  {d}│{rst}  {cy}{icon_label:<14}{rst} {w}{value}{rst}")

    print(f"  {d}{'─' * 61}{rst}")
    print()


# ── Styled Logger ────────────────────────────────────────────

class NzoyiFormatter(logging.Formatter):
    """Custom log formatter with colors and icons."""

    LEVEL_STYLES = {
        logging.DEBUG: (Color.DIM, "DBG"),
        logging.INFO: (Color.CYAN, "INF"),
        logging.WARNING: (Color.YELLOW, "WRN"),
        logging.ERROR: (Color.RED, "ERR"),
        logging.CRITICAL: (Color.RED, "CRT"),
    }

    def format(self, record: logging.LogRecord) -> str:
        color, tag = self.LEVEL_STYLES.get(record.levelno, (Color.WHITE, "???"))
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

        if Color.strip():
            return f"{ts} [{tag}] {record.name.split('.')[-1]:>12} │ {record.getMessage()}"

        name = record.name.replace("nzoyi.", "")
        return (
            f"{Color.DIM}{ts}{Color.RESET} "
            f"{color}[{tag}]{Color.RESET} "
            f"{Color.GOLD}{name:>12}{Color.RESET} "
            f"{Color.DIM}│{Color.RESET} "
            f"{record.getMessage()}"
        )


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure NZOYI-styled console logging."""
    handler = logging.StreamHandler()
    handler.setFormatter(NzoyiFormatter())
    handler.setLevel(level)

    logger = logging.getLogger("nzoyi")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)
    return logger


# ── Progress & Status ────────────────────────────────────────

def print_agent_status(name: str, status: str, detail: str = "") -> None:
    """Print a single agent execution status line."""
    icons = {
        "running": f"{Color.AMBER}⏳{Color.RESET}",
        "done": f"{Color.GREEN}✓{Color.RESET}",
        "fail": f"{Color.RED}✗{Color.RESET}",
        "error": f"{Color.RED}✗{Color.RESET}",
        "skip": f"{Color.DIM}○{Color.RESET}",
    }
    if Color.strip():
        icons = {
            "running": "...", "done": "[OK]", "fail": "[FAIL]",
            "error": "[FAIL]", "skip": "[-]",
        }

    icon = icons.get(status, "?")
    det = f" {Color.DIM}({detail}){Color.RESET}" if detail else ""
    if Color.strip() and detail:
        det = f" ({detail})"

    print(f"  {icon} {name:<20}{det}")


def print_result_box(title: str, data: dict[str, Any]) -> None:
    """Print a styled result summary."""
    a, w, d, gn, rst = Color.AMBER, Color.WHITE, Color.DIM, Color.GREEN, Color.RESET
    if Color.strip():
        a = w = d = gn = rst = ""

    print()
    print(f"  {a}{'═' * 50}{rst}")
    print(f"  {a}  {title}{rst}")
    print(f"  {a}{'═' * 50}{rst}")
    for key, val in data.items():
        print(f"  {d}│{rst}  {w}{key:<25}{rst} {gn}{val}{rst}")
    print(f"  {a}{'═' * 50}{rst}")
    print()


def print_test_result(name: str, passed: bool) -> None:
    """Print a single test result line."""
    if passed:
        icon = f"{Color.GREEN}✓{Color.RESET}" if not Color.strip() else "[PASS]"
    else:
        icon = f"{Color.RED}✗{Color.RESET}" if not Color.strip() else "[FAIL]"
    print(f"  {icon} {name}")
