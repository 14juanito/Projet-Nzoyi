"""Terminal UI — ASCII banner, colored boxes, and logging for NZOYI."""

from __future__ import annotations

import logging
import sys
from typing import Any

# ── TTY detection ──────────────────────────────────────────────────────────
_IS_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Color:
    """ANSI color codes — amber/wasp theme."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    AMBER = "\033[38;5;214m"
    GOLD = "\033[38;5;220m"
    ORANGE = "\033[38;5;208m"
    HONEY = "\033[38;5;179m"
    WHITE = "\033[97m"
    GREEN = "\033[38;5;82m"
    RED = "\033[38;5;196m"
    CYAN = "\033[38;5;51m"
    GREY = "\033[38;5;245m"


def _c(text: str, *codes: str) -> str:
    if not _IS_TTY:
        return text
    return "".join(codes) + text + Color.RESET


def _box_line(content: str, width: int = 62) -> str:
    inner = content[: width - 4]
    return f"║ {inner:<{width - 4}} ║"


ASCII_LOGO = r"""
 ███╗   ██╗███████╗ ██████╗ ██╗   ██╗██╗
 ████╗  ██║╚══███╔╝██╔═══██╗╚██╗ ██╔╝██║
 ██╔██╗ ██║  ███╔╝ ██║   ██║ ╚████╔╝ ██║
 ██║╚██╗██║ ███╔╝  ██║   ██║  ╚██╔╝  ██║
 ██║ ╚████║███████╗╚██████╔╝   ██║   ██║
 ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝
""".strip("\n")


def print_banner(version: str) -> None:
    lines = ASCII_LOGO.split("\n")
    for line in lines:
        print(_c(line, Color.BOLD, Color.ORANGE))
    print()

    border = _c("╔" + "═" * 62 + "╗", Color.AMBER)
    footer = _c("╚" + "═" * 62 + "╝", Color.AMBER)
    print(border)
    for text in (
        f"🐝 NZOYI v{version} — Multi-Agent IDS Resilience Framework",
        "⚡ Adaptive Q-Learning Evasion Engine",
        "🛡️ Defensive Research · IDS Robustness Testing",
        "🔬 Cybernetic Feedback Loop · 7 Autonomous Agents",
    ):
        print(_c(_box_line(text), Color.GOLD))
    print(footer)
    print()


def print_config_box(
    target: str,
    profile: str,
    mode: str,
    cycles: int,
    eve_log: str | None,
) -> None:
    border = _c("┌" + "─" * 50 + "┐", Color.HONEY)
    footer = _c("└" + "─" * 50 + "┘", Color.HONEY)
    print(border)
    rows = [
        ("Target", target),
        ("Profile", profile),
        ("Mode", mode),
        ("Cycles", str(cycles)),
        ("EVE log", eve_log or "(simulated)"),
    ]
    for label, value in rows:
        line = f"│ {label:<10} {_c(value, Color.WHITE)}"
        print(_c(line, Color.HONEY) if _IS_TTY else f"│ {label:<10} {value}")
    print(footer)
    print()


def print_agent_status(name: str, status: str, detail: str = "") -> None:
    icons = {"running": "▶", "done": "✓", "error": "✗", "skip": "○"}
    colors = {
        "running": Color.AMBER,
        "done": Color.GREEN,
        "error": Color.RED,
        "skip": Color.GREY,
    }
    icon = icons.get(status, "·")
    color = colors.get(status, Color.WHITE)
    msg = f"  {icon} {_c(name.upper(), Color.BOLD, color):<16}"
    if detail:
        msg += _c(detail, Color.DIM)
    print(msg)


def print_result_box(title: str, data: dict[str, Any]) -> None:
    print(_c(f"┌─ {title} " + "─" * max(0, 44 - len(title)), Color.ORANGE))
    for key, value in data.items():
        print(_c(f"│ {key}: ", Color.HONEY) + str(value))
    print(_c("└" + "─" * 48, Color.ORANGE))
    print()


def print_test_result(name: str, passed: bool) -> None:
    if passed:
        print(_c(f"  ✓ {name}", Color.GREEN))
    else:
        print(_c(f"  ✗ {name}", Color.RED))


class NzoyiFormatter(logging.Formatter):
  """Colored log formatter with agent icons."""

  ICONS = {
      logging.DEBUG: "🔍",
      logging.INFO: "🐝",
      logging.WARNING: "⚠️",
      logging.ERROR: "❌",
      logging.CRITICAL: "🔥",
  }

  def format(self, record: logging.LogRecord) -> str:
      icon = self.ICONS.get(record.levelno, "·")
      if _IS_TTY:
          level_color = {
              logging.DEBUG: Color.GREY,
              logging.INFO: Color.AMBER,
              logging.WARNING: Color.GOLD,
              logging.ERROR: Color.RED,
          }.get(record.levelno, Color.WHITE)
          level = _c(record.levelname, level_color)
          return f"{icon} {level} {_c(record.name, Color.DIM)} — {record.getMessage()}"
      return f"{icon} {record.levelname} {record.name} — {record.getMessage()}"


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("nzoyi")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(NzoyiFormatter())
        logger.addHandler(handler)
    return logger
