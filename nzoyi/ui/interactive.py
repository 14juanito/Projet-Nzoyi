"""
NZOYI — Interactive terminal interface.
Provides menu-driven interaction and autonomous execution mode.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from nzoyi.ui.banner import (
    Color,
    c,
    print_agent_status,
    print_banner,
    print_result_box,
)


# ── Input helpers ────────────────────────────────────────────

def prompt(text: str, default: str = "") -> str:
    """Styled input prompt."""
    d = f" {Color.DIM}[{default}]{Color.RESET}" if default else ""
    if Color.strip():
        d = f" [{default}]" if default else ""
    try:
        val = input(f"  {Color.AMBER}›{Color.RESET} {text}{d}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def prompt_choice(text: str, options: list[tuple[str, str]], default: str = "1") -> str:
    """Display numbered options and return the selected key."""
    print(f"\n  {Color.GOLD}{text}{Color.RESET}")
    for i, (key, label) in enumerate(options, 1):
        marker = f"{Color.AMBER}›{Color.RESET}" if str(i) == default else " "
        print(f"  {marker} {Color.CYAN}{i}{Color.RESET}. {label}")
    choice = prompt("Choix", default)
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx][0]
    except ValueError:
        for key, _ in options:
            if choice.lower() == key.lower():
                return key
    return options[0][0]


def prompt_confirm(text: str, default: bool = True) -> bool:
    """Yes/No prompt."""
    hint = "O/n" if default else "o/N"
    val = prompt(f"{text} ({hint})", "o" if default else "n")
    return val.lower() in ("o", "oui", "y", "yes", "")


def print_section(title: str) -> None:
    """Print a section divider."""
    print(f"\n  {Color.GOLD}{'─' * 55}{Color.RESET}")
    print(f"  {Color.GOLD}  {title}{Color.RESET}")
    print(f"  {Color.GOLD}{'─' * 55}{Color.RESET}\n")


# ── Typing animation ────────────────────────────────────────

def typewrite(text: str, delay: float = 0.02) -> None:
    """Print text with typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        if char not in (" ", "\n"):
            time.sleep(delay)
    print()


# ── Main interactive flow ────────────────────────────────────

class InteractiveSession:
    """Interactive terminal session for NZOYI."""

    def __init__(self, version: str = "0.1.0"):
        self.version = version
        self.target: str = ""
        self.profile: str = ""
        self.mode: str = ""
        self.cycles: int = 100
        self.eve_log: str | None = None
        self.dry_run: bool = False

    def start(self) -> dict[str, Any]:
        """Full interactive startup flow. Returns {} if cancelled."""
        print_banner(self.version)

        typewrite(
            f"  {Color.DIM}Initialisation du système multi-agent...{Color.RESET}", 0.01
        )
        print()

        # Step 1: Target
        print_section("1 · CIBLE")
        self.target = prompt("Adresse IP de la cible", "192.168.100.11")

        # Step 2: Profile
        print_section("2 · PROFIL D'ATTAQUE")
        self.profile = prompt_choice(
            "Sélectionne un profil :",
            [
                ("stealth", f"🥷  Stealth    {Color.DIM}— Lent, fragmenté, furtif (recommandé){Color.RESET}"),
                ("default", f"⚖️  Balanced   {Color.DIM}— Compromis vitesse/furtivité{Color.RESET}"),
                ("aggressive", f"⚡ Aggressive {Color.DIM}— Rapide, bruyant (baseline){Color.RESET}"),
            ],
            default="1",
        )

        # Step 3: Mode
        print_section("3 · MODE D'EXÉCUTION")
        self.mode = prompt_choice(
            "Comment veux-tu piloter les agents ?",
            [
                ("guided", f"🎮 Guidé      {Color.DIM}— Tu confirmes chaque étape{Color.RESET}"),
                ("autonomous", f"🤖 Autonome   {Color.DIM}— Les agents agissent seuls, tu observes{Color.RESET}"),
                ("learning", f"🧠 Apprentissage {Color.DIM}— Boucle RL complète (N cycles){Color.RESET}"),
            ],
            default="1",
        )

        if self.mode == "learning":
            cycles_str = prompt("Nombre de cycles Q-Learning", "100")
            self.cycles = int(cycles_str) if cycles_str.isdigit() else 100

        # Step 4: IDS feedback
        print_section("4 · FEEDBACK IDS")
        has_suricata = prompt_choice(
            "As-tu accès aux logs Suricata (eve.json) ?",
            [
                ("yes", f"✅ Oui  {Color.DIM}— Suricata tourne sur la cible{Color.RESET}"),
                ("no", f"❌ Non  {Color.DIM}— Mode simulation (pas d'IDS réel){Color.RESET}"),
            ],
            default="2",
        )
        if has_suricata == "yes":
            self.eve_log = prompt("Chemin vers eve.json", "/var/log/suricata/eve.json")

        if has_suricata == "no":
            self.dry_run = prompt_confirm(
                f"  {Color.YELLOW}⚠{Color.RESET}  Mode dry-run (simulation sans réseau réel) ?",
                default=True,
            )

        # Step 5: Summary
        print_section("5 · RÉCAPITULATIF")
        mode_labels = {
            "guided": "🎮 Guidé",
            "autonomous": "🤖 Autonome",
            "learning": f"🧠 Apprentissage ({self.cycles} cycles)",
        }
        summary_data = {
            "Cible": self.target,
            "Profil": self.profile,
            "Mode": mode_labels.get(self.mode, self.mode),
            "IDS Feedback": self.eve_log or "Simulation",
            "Dry Run": "Oui" if self.dry_run else "Non",
        }
        for key, val in summary_data.items():
            print(f"  {Color.DIM}│{Color.RESET}  {Color.CYAN}{key:<18}{Color.RESET} {val}")
        print()

        if not prompt_confirm("Lancer l'exécution ?", default=True):
            print(f"\n  {Color.DIM}Annulé.{Color.RESET}\n")
            return {}

        return {
            "target": self.target,
            "profile": self.profile,
            "mode": self.mode,
            "cycles": self.cycles,
            "eve_log": self.eve_log,
            "dry_run": self.dry_run,
        }


# ── Guided execution ─────────────────────────────────────────

class GuidedRunner:
    """Runs the pipeline step-by-step with user confirmation."""

    AGENT_DESCRIPTIONS = {
        "recon": "Le Recon Agent va scanner la cible avec Nmap pour découvrir les ports ouverts et les services actifs.",
        "enumerator": "L'Enumerator Agent va approfondir les résultats : versions des services, bannières, fingerprinting.",
        "vulnerability": "Le Vuln Analyzer va mapper les services découverts à des CVEs connues.",
        "evasion": "L'Evasion Agent va consulter le Q-Learning et choisir une stratégie d'évasion.",
        "attack": "L'Attack Agent va exécuter l'exploit en appliquant les paramètres d'évasion.",
        "evaluation": "L'Evaluation Agent va lire les logs Suricata pour déterminer si l'attaque a été détectée.",
    }

    def run_agent_guided(self, agent, dry_run: bool, eve_log: str | None = None) -> dict | None:
        """Execute a single agent with user interaction. None => user quit."""
        name = agent.name
        desc = self.AGENT_DESCRIPTIONS.get(name, "")

        print(f"\n  {Color.GOLD}┌─ Agent: {name.upper()} {'─' * max(0, 40 - len(name))}{Color.RESET}")
        if desc:
            print(f"  {Color.DIM}│ {desc}{Color.RESET}")
        print(f"  {Color.GOLD}└{'─' * 50}{Color.RESET}\n")

        action = prompt_choice(
            f"Action pour {name} :",
            [
                ("run", "▶  Exécuter"),
                ("skip", "⏭  Passer cet agent"),
                ("quit", "⏹  Arrêter le pipeline"),
            ],
            default="1",
        )

        if action == "quit":
            return None
        if action == "skip":
            print_agent_status(name, "skip", "ignoré par l'utilisateur")
            return {"skipped": True}

        print_agent_status(name, "running")
        t0 = time.time()
        result = self._execute(agent, dry_run, eve_log)
        duration = time.time() - t0

        if not Color.strip():
            print("\033[A", end="")
        detail = self._format_detail(name, result)
        print_agent_status(name, "done", f"{detail} · {duration:.1f}s")

        print(f"\n  {Color.DIM}Résultat:{Color.RESET}")
        for k, v in result.items():
            val_str = str(v)
            if len(val_str) > 60:
                val_str = val_str[:57] + "..."
            print(f"    {Color.CYAN}{k:<20}{Color.RESET} {val_str}")
        print()
        return result

    @staticmethod
    def _execute(agent, dry_run: bool, eve_log: str | None) -> dict:
        from nzoyi.agents.evaluation import EvaluationAgent

        if isinstance(agent, EvaluationAgent):
            return agent.run(dry_run=dry_run, eve_log=eve_log)
        return agent.run(dry_run=dry_run)

    @staticmethod
    def _format_detail(name: str, result: dict) -> str:
        if name == "recon":
            return f"{len(result.get('open_ports', []))} ports"
        if name == "vulnerability":
            return f"{len(result.get('findings', []))} vulns"
        if name == "evasion":
            return f"action={result.get('action', '?')}"
        if name == "evaluation":
            return f"alerts={result.get('alert_count', 0)}"
        return ""


# ── Autonomous execution ─────────────────────────────────────

class AutonomousRunner:
    """Runs the full pipeline without user interaction."""

    def run_pipeline(self, orchestrator, dry_run: bool, eve_log: str | None = None) -> dict:
        from nzoyi.agents.evaluation import EvaluationAgent

        print(f"\n  {Color.AMBER}🤖 Mode autonome — les agents prennent le contrôle{Color.RESET}\n")

        results: dict[str, Any] = {}
        for agent in orchestrator.pipeline:
            name = agent.name
            print_agent_status(name, "running")
            t0 = time.time()

            if isinstance(agent, EvaluationAgent):
                result = agent.run(dry_run=dry_run, eve_log=eve_log)
            else:
                result = agent.run(dry_run=dry_run)

            duration = time.time() - t0
            results[name] = result

            if not Color.strip():
                print("\033[A", end="")
            detail = self._short_detail(name, result)
            print_agent_status(name, "done", f"{detail} · {duration:.1f}s")

        return results

    @staticmethod
    def _short_detail(name: str, result: dict) -> str:
        if name == "recon":
            return f"{len(result.get('open_ports', []))} ports"
        if name == "evasion":
            return f"{result.get('action', '?')}"
        if name == "evaluation":
            return f"alerts={result.get('alert_count', 0)}"
        if name == "vulnerability":
            return f"{len(result.get('findings', []))} vulns"
        return ""


# ── Learning loop display ────────────────────────────────────

class LearningRunner:
    """Runs the RL learning loop with live progress display."""

    def run(self, orchestrator, cycles: int, dry_run: bool, eve_log: str | None = None) -> dict:
        from nzoyi.agents.evaluation import EvaluationAgent
        from nzoyi.agents.evasion import EvasionAgent

        print(f"\n  {Color.AMBER}🧠 Boucle d'apprentissage — {cycles} cycles{Color.RESET}")
        print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")
        print(f"  {'Cycle':<8} {'Détecté':<10} {'Reward':<10} {'ε':<10} {'Détection %':<12}")
        print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")

        # Run recon/enum/vuln once.
        for agent in orchestrator.pipeline[:3]:
            agent.run(dry_run=dry_run)

        evasion_agent = next((a for a in orchestrator.pipeline if isinstance(a, EvasionAgent)), None)
        attack_agent = next((a for a in orchestrator.pipeline if a.name == "attack"), None)
        eval_agent = next((a for a in orchestrator.pipeline if isinstance(a, EvaluationAgent)), None)

        convergence: list[dict[str, Any]] = []
        total_detected = 0

        for i in range(1, cycles + 1):
            ev_result = evasion_agent.run(dry_run=dry_run) if evasion_agent else {}
            if attack_agent:
                attack_agent.run(dry_run=dry_run)
            eval_result = (
                eval_agent.run(dry_run=dry_run, eve_log=eve_log) if eval_agent else {}
            )

            # Prefer the IDS verdict when Suricata feedback is available.
            if eval_result.get("source", "simulated") not in ("simulated", ""):
                detected = bool(eval_result.get("detected", False))
            else:
                detected = bool(ev_result.get("detected", False))

            # Close the cybernetic loop: update Q-Learning from feedback.
            if evasion_agent:
                learn_result = evasion_agent.learn(detected)
                reward = learn_result["reward"]
                epsilon = evasion_agent.learner.epsilon
            else:
                reward, epsilon = 0.0, 0.0

            if detected:
                total_detected += 1
            det_rate = total_detected / i

            convergence.append({
                "cycle": i,
                "detected": detected,
                "reward": reward,
                "detection_rate": round(det_rate, 4),
                "epsilon": round(epsilon, 4),
            })

            if i <= 3 or i % 10 == 0 or i == cycles:
                if Color.strip():
                    det_icon = "OUI" if detected else "NON"
                    rew_str = f"+{reward:.1f}" if reward > 0 else f"{reward:.1f}"
                else:
                    det_icon = f"{Color.RED}OUI{Color.RESET}" if detected else f"{Color.GREEN}NON{Color.RESET}"
                    rew_str = (
                        f"{Color.GREEN}+{reward:.1f}{Color.RESET}"
                        if reward > 0
                        else f"{Color.RED}{reward:.1f}{Color.RESET}"
                    )
                print(f"  {i:<8} {det_icon:<19} {rew_str:<19} {epsilon:<10.4f} {det_rate:<12.1%}")

        print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")

        final_rate = total_detected / cycles if cycles > 0 else 0.0
        print_result_box("Résultats de l'apprentissage", {
            "Cycles complétés": cycles,
            "Taux de détection final": f"{final_rate:.1%}",
            "Total détections": f"{total_detected}/{cycles}",
            "Epsilon final": f"{convergence[-1]['epsilon']:.4f}" if convergence else "?",
        })

        return {"convergence": convergence, "final_detection_rate": final_rate}
