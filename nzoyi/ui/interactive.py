"""
NZOYI — Interactive terminal interface.
Provides menu-driven interaction and autonomous execution mode.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from nzoyi.ui.banner import (
    Color,
    c,
    print_agent_status,
    print_banner,
    print_result_box,
)

# Passerelle locale (miroir SSH de Suricata) — pas /var/log sur la cible.
DEFAULT_EVE_LOG = "/tmp/eve.json"


# ── Input helpers ────────────────────────────────────────────

def prompt(text: str, default: str = "") -> str:
    """Styled input prompt. Affiche [défaut] seulement si un défaut est fourni."""
    d = f" {Color.DIM}[{default}]{Color.RESET}" if default else ""
    if Color.strip() and default:
        d = f" [{default}]"
    try:
        val = input(f"  {Color.AMBER}›{Color.RESET} {text}{d}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def prompt_choice(text: str, options: list[tuple[str, str]], default: str = "") -> str:
    """Display numbered options; exige un choix explicite (pas de défaut silencieux)."""
    print(f"\n  {Color.GOLD}{text}{Color.RESET}")
    for i, (key, label) in enumerate(options, 1):
        print(f"    {Color.CYAN}{i}{Color.RESET}. {label}")
    while True:
        choice = prompt("Choix (numéro)", default)
        if not choice:
            print(f"  {Color.DIM}Entre un numéro parmi 1–{len(options)}.{Color.RESET}")
            continue
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            for key, _ in options:
                if choice.lower() == key.lower():
                    return key
        print(f"  {Color.DIM}Choix invalide — réessaie.{Color.RESET}")


def prompt_confirm(text: str, default: bool = True) -> bool:
    """Yes/No prompt (confirmation essentielle)."""
    hint = "O/n" if default else "o/N"
    val = prompt(f"{text} ({hint})", "o" if default else "n")
    return val.lower() in ("o", "oui", "y", "yes", "")


def require_eve_log(path: str) -> bool:
    """Vérifie que eve.json existe et contient déjà du trafic Suricata."""
    eve = Path(path)
    if not eve.is_file():
        print(
            f"\n  {Color.RED}✗ eve.json introuvable : {path}{Color.RESET}\n"
            f"  {Color.DIM}Lance d'abord la passerelle SSH qui miroire Suricata "
            f"vers {DEFAULT_EVE_LOG}, puis relance.{Color.RESET}\n"
        )
        return False
    if eve.stat().st_size == 0:
        print(
            f"\n  {Color.RED}✗ eve.json est vide : {path}{Color.RESET}\n"
            f"  {Color.DIM}Le fichier existe mais ne se remplit pas — vérifie que "
            f"la passerelle SSH tourne et que Suricata écrit des événements.{Color.RESET}\n"
        )
        return False
    return True


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
        while True:
            self.target = prompt("Adresse IP de la cible", "")
            if self.target:
                break
            print(f"  {Color.DIM}La cible est obligatoire.{Color.RESET}")

        # Step 2: Profile
        print_section("2 · PROFIL D'ATTAQUE")
        self.profile = prompt_choice(
            "Sélectionne un profil :",
            [
                ("stealth", f"🥷  Stealth    {Color.DIM}— Lent, fragmenté, furtif (recommandé){Color.RESET}"),
                ("default", f"⚖️  Balanced   {Color.DIM}— Compromis vitesse/furtivité{Color.RESET}"),
                ("aggressive", f"⚡ Aggressive {Color.DIM}— Rapide, bruyant (baseline){Color.RESET}"),
            ],
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
        )

        if self.mode == "learning":
            while True:
                cycles_str = prompt("Nombre de cycles Q-Learning", "")
                if cycles_str.isdigit() and int(cycles_str) > 0:
                    self.cycles = int(cycles_str)
                    break
                print(f"  {Color.DIM}Entre un entier > 0.{Color.RESET}")

        # Step 4: IDS feedback (réel uniquement — pas de mode simulation)
        print_section("4 · FEEDBACK IDS")
        print(
            f"  {Color.DIM}Suricata réel requis via la passerelle locale "
            f"({DEFAULT_EVE_LOG}).{Color.RESET}"
        )
        self.eve_log = prompt("Chemin vers eve.json", DEFAULT_EVE_LOG)
        if not require_eve_log(self.eve_log):
            return {}
        self.dry_run = False  # mode réel strict

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
            "IDS Feedback": self.eve_log,
            "Mode réseau": "RÉEL (pas de simulation)",
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
            "dry_run": False,
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

    def __init__(self) -> None:
        self._eval_agent: Any = None

    def bind_evaluation(self, eval_agent) -> None:
        """Référence l'EvaluationAgent du pipeline (pour baseline_ids avant attack)."""
        self._eval_agent = eval_agent

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

        # Avant l'attaque : ignore les alertes recon/vuln (comme Autonome / Apprentissage).
        if name == "attack" and eve_log and self._eval_agent is not None:
            self._eval_agent.baseline_ids(eve_log)

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
        from nzoyi.ui.live_ops import LiveOpsConsole

        profile_name = getattr(orchestrator.profile, "name", "stealth")
        live = LiveOpsConsole(
            target=orchestrator.ptt.target,
            profile=profile_name,
            eve_log=eve_log,
            cycles_total=1,
        )

        if live.enabled:
            print(f"\n  {Color.AMBER}🤖 Mode autonome — Live Ops TUI{Color.RESET}\n")
            live.start()
        else:
            print(f"\n  {Color.AMBER}🤖 Mode autonome — les agents prennent le contrôle{Color.RESET}\n")

        results: dict[str, Any] = {}
        try:
            for agent in orchestrator.pipeline:
                name = agent.name
                if not live.enabled:
                    print_agent_status(name, "running")
                live.push_agent_event(name, "running")
                orchestrator._write_run_state(orchestrator._run_state(name, "running"))
                t0 = time.time()

                # Avant l'attaque : ignore les alertes du recon/enum.
                if name == "attack":
                    for a in orchestrator.pipeline:
                        if isinstance(a, EvaluationAgent):
                            a.baseline_ids(eve_log)
                            break

                if isinstance(agent, EvaluationAgent):
                    result = agent.run(dry_run=dry_run, eve_log=eve_log)
                else:
                    result = agent.run(dry_run=dry_run)

                duration = time.time() - t0
                results[name] = result

                orchestrator._write_run_state(orchestrator._run_state(
                    name, "done",
                    duration=round(duration, 3),
                    result=orchestrator._summarize_result(name, result),
                ))
                orchestrator._write_ptt_state()

                detail = self._short_detail(name, result)
                live.push_agent_event(name, f"done {detail} · {duration:.1f}s")

                if name == "recon":
                    live.update_cycle(
                        cycle=0,
                        ports=result.get("open_ports", []),
                    )
                elif name == "vulnerability":
                    live.update_cycle(
                        cycle=0,
                        vulns=len(result.get("findings", [])),
                        ports=[p["port"] for p in orchestrator.ptt.get_recon_results()],
                    )
                elif name == "evasion":
                    live.update_cycle(cycle=0, action=result.get("action"))
                elif name == "evaluation":
                    live.update_cycle(
                        cycle=1,
                        alert_count=int(result.get("alert_count") or 0),
                        rf_proba=float(result.get("rf_proba") or 0.0),
                        detected=bool(result.get("detected", False)),
                        ports=[p["port"] for p in orchestrator.ptt.get_recon_results()],
                        vulns=len(orchestrator.ptt.get_vulnerabilities()),
                        action=(results.get("evasion") or {}).get("action"),
                    )

                if not live.enabled:
                    if not Color.strip():
                        print("\033[A", end="")
                    print_agent_status(name, "done", f"{detail} · {duration:.1f}s")
        finally:
            live.stop()

        orchestrator._write_run_state(orchestrator._run_state("orchestrator", "complete"))
        orchestrator._write_ptt_state()
        self._print_debrief(results)
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

    @staticmethod
    def _print_debrief(results: dict[str, Any]) -> None:
        """Résumé narratif de ce que les agents ont réellement fait."""
        recon = results.get("recon", {})
        enum = results.get("enumerator", {})
        vuln = results.get("vulnerability", {})
        evasion = results.get("evasion", {})
        attack = results.get("attack", {})
        evaluation = results.get("evaluation", {})

        ports = recon.get("open_ports", [])
        n_services = len(enum.get("service_list", []))
        n_vulns = len(vuln.get("findings", []))
        action = evasion.get("action", "—")
        alerts = evaluation.get("alert_count", 0)
        rf_proba = evaluation.get("rf_proba", 0.0)
        rf_ok = evaluation.get("rf_detected") is not None and evaluation.get("source") != "unavailable"
        suricata = evaluation.get("suricata_detected", False)
        executed = attack.get("executed", False)
        timed_out = attack.get("timed_out", False)

        print(f"\n  {Color.GOLD}{'─' * 55}{Color.RESET}")
        print(f"  {Color.GOLD}  DÉBRIEF — ce que les agents ont fait{Color.RESET}")
        print(f"  {Color.GOLD}{'─' * 55}{Color.RESET}\n")

        print(f"  {Color.CYAN}• Recon{Color.RESET}        : {len(ports)} port(s) ouvert(s) → {ports or 'aucun'}")
        print(f"  {Color.CYAN}• Enumerator{Color.RESET}  : {n_services} service(s) fingerprinté(s)")
        print(f"  {Color.CYAN}• Vuln{Color.RESET}         : {n_vulns} CVE(s) corrélée(s)")
        print(f"  {Color.CYAN}• Evasion{Color.RESET}      : action Q-Learning « {action} »")
        if timed_out:
            print(f"  {Color.CYAN}• Attack{Color.RESET}       : non aboutie (timeout)")
        elif executed:
            print(f"  {Color.CYAN}• Attack{Color.RESET}       : stimulus nmap envoyé sur {ports}")
        else:
            print(f"  {Color.CYAN}• Attack{Color.RESET}       : aucun stimulus (ports/plan)")

        alert_line = f"{alerts} alerte(s) Suricata"
        if suricata:
            alert_line += f" {Color.RED}(détecté){Color.RESET}"
        else:
            alert_line += f" {Color.GREEN}(furtif côté signatures){Color.RESET}"
        print(f"  {Color.CYAN}• Evaluation{Color.RESET}   : {alert_line}")
        print(
            f"  {Color.CYAN}• RF Oracle{Color.RESET}    : score={rf_proba:.2f} "
            f"(seuil détection ML)"
        )

        # Lecture métier : plus d'alertes = plus bruyant ; RF bas = plus discret.
        if alerts == 0 and rf_proba < 0.5:
            verdict = (
                f"{Color.GREEN}Les agents ont réduit l'empreinte : "
                f"0 alerte Suricata et score RF sous le seuil.{Color.RESET}"
            )
        elif alerts > 0 and rf_proba < 0.5:
            verdict = (
                f"{Color.AMBER}Suricata a encore vu du bruit ({alerts} alertes), "
                f"mais le RF reste sous le seuil ({rf_proba:.2f}) — "
                f"évasion partielle.{Color.RESET}"
            )
        elif alerts == 0 and rf_proba >= 0.5:
            verdict = (
                f"{Color.AMBER}Pas d'alerte signature, mais le RF classe encore "
                f"comme attaque (score={rf_proba:.2f}).{Color.RESET}"
            )
        else:
            verdict = (
                f"{Color.RED}Empreinte forte : {alerts} alerte(s) Suricata et "
                f"RF score={rf_proba:.2f}. La boucle d'apprentissage "
                f"(mode Apprentissage) doit encore optimiser l'évasion.{Color.RESET}"
            )
        print(f"\n  {verdict}\n")


# ── Learning loop display ────────────────────────────────────

def _fmt_detected(detected: bool) -> str:
    if Color.strip():
        return "OUI" if detected else "NON"
    if detected:
        return f"{Color.RED}OUI{Color.RESET}"
    return f"{Color.GREEN}NON{Color.RESET}"


def _fmt_reward(reward: float) -> str:
    if Color.strip():
        return f"+{reward:.1f}" if reward > 0 else f"{reward:.1f}"
    if reward > 0:
        return f"{Color.GREEN}+{reward:.1f}{Color.RESET}"
    return f"{Color.RED}{reward:.1f}{Color.RESET}"


def _print_cycle_table(convergence: list[dict[str, Any]], *, title: str | None = None) -> None:
    """Tableau Cycle / Détecté / Reward / ε / Détection %."""
    if title:
        print(f"\n  {Color.AMBER}{title}{Color.RESET}")
    print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")
    print(f"  {'Cycle':<8} {'Détecté':<10} {'Reward':<10} {'ε':<10} {'Détection %':<12}")
    print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")
    for row in convergence:
        print(
            f"  {row['cycle']:<8} {_fmt_detected(row['detected']):<19} "
            f"{_fmt_reward(row['reward']):<19} {row['epsilon']:<10.4f} "
            f"{row['detection_rate']:<12.1%}"
        )
    print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")


class LearningRunner:
    """Runs the RL learning loop with live progress display."""

    def run(self, orchestrator, cycles: int, dry_run: bool, eve_log: str | None = None) -> dict:
        from nzoyi.agents.evaluation import EvaluationAgent
        from nzoyi.agents.evasion import EvasionAgent
        from nzoyi.ui.live_ops import LiveOpsConsole

        profile_name = getattr(orchestrator.profile, "name", "stealth")
        live = LiveOpsConsole(
            target=orchestrator.ptt.target,
            profile=profile_name,
            eve_log=eve_log,
            cycles_total=cycles,
        )

        if not live.enabled:
            print(f"\n  {Color.AMBER}🧠 Boucle d'apprentissage — {cycles} cycles{Color.RESET}")
            print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")
            print(f"  {'Cycle':<8} {'Détecté':<10} {'Reward':<10} {'ε':<10} {'Détection %':<12}")
            print(f"  {Color.DIM}{'─' * 55}{Color.RESET}")
        else:
            print(
                f"\n  {Color.AMBER}🧠 Boucle d'apprentissage — Live Ops "
                f"({cycles} cycles){Color.RESET}\n"
            )
            live.start()

        # Couche stratégique LLM — jusqu'à ce correctif (diagnostic J7),
        # LearningRunner ne l'appelait JAMAIS, contrairement à
        # OrchestratorAgent.run()/.learn()/.finetune_online() : le plan
        # stratégique (triage CVE, priorisation de ports) n'avait donc aucun
        # effet sur la campagne, ni sur AttackAgent.target_ports/focus_services
        # ni (transitivement) sur EvasionAgent — voir _apply_plan().
        #
        # `--profile` reste l'autorité de CE runner : on gèle explicitement
        # le profil choisi en CLI après chaque appel stratégique, pour que
        # le LLM puisse influencer target_ports/focus_services (et donc
        # EvasionAgent.target_signature) SANS jamais pouvoir remplacer en
        # silence le profil d'attaque demandé par l'opérateur — un second
        # facteur de variance non contrôlé que l'on ne veut pas introduire
        # dans un comparatif inter-backends (J7).
        frozen_profile = orchestrator.profile
        orchestrator._strategic_plan()
        orchestrator._apply_profile(frozen_profile)

        # Run recon/enum/vuln once.
        for agent in orchestrator.pipeline[:3]:
            live.push_agent_event(agent.name, "running")
            orchestrator._write_run_state(orchestrator._run_state(agent.name, "running"))
            step_result = agent.run(dry_run=dry_run)
            orchestrator._write_run_state(orchestrator._run_state(
                agent.name, "done",
                result=orchestrator._summarize_result(agent.name, step_result),
            ))
            orchestrator._write_ptt_state()
            detail = ""
            if agent.name == "recon":
                detail = f"ports={step_result.get('open_ports', [])}"
            elif agent.name == "vulnerability":
                detail = f"findings={len(step_result.get('findings', []))}"
            live.push_agent_event(agent.name, f"done {detail}".strip())

        if not orchestrator.ptt.get_recon_results():
            live.stop()
            print(
                f"\n  {Color.RED}✗ Recon initial n'a trouvé aucun port ouvert "
                f"— campagne annulée.{Color.RESET}\n"
            )
            orchestrator.ptt.add(
                orchestrator.name, "campaign_aborted", {"reason": "recon initial vide"}
            )
            orchestrator._write_run_state(
                orchestrator._run_state("orchestrator", "aborted", reason="recon_empty")
            )
            orchestrator._write_ptt_state()
            return {"convergence": [], "final_detection_rate": 0.0, "aborted": True}

        # Replan stratégique UNE fois, PTT maintenant enrichi par
        # recon/enum/vuln (ports réels, CVE corrélées) — c'est cet appel qui
        # peuple réellement AttackAgent.target_ports/focus_services ET
        # EvasionAgent.target_ports via _apply_plan(). `plan["lancer_boucle_
        # evasion"]` est DÉLIBÉRÉMENT ignoré ici : `cycles` reste la seule
        # autorité de ce runner (contrat déjà documenté par
        # OrchestratorAgent.learning_loop() pour l'argument `cycles`) — un
        # plan qui déciderait de ne pas lancer l'évasion ne doit jamais
        # produire une campagne à 0 cycle non sollicitée par l'opérateur,
        # surtout pour un harness de comparatif (J7) qui exige un nombre de
        # cycles fixe et identique par backend.
        replan = orchestrator._strategic_replan()
        orchestrator._apply_profile(frozen_profile)
        orchestrator.ptt.add(orchestrator.name, "llm_decision", replan, allow_duplicate=True)
        orchestrator._apply_plan(replan)

        ports = [p["port"] for p in orchestrator.ptt.get_recon_results()]
        vulns = len(orchestrator.ptt.get_vulnerabilities())
        live.update_cycle(cycle=0, ports=ports, vulns=vulns)

        evasion_agent = next((a for a in orchestrator.pipeline if isinstance(a, EvasionAgent)), None)
        attack_agent = next((a for a in orchestrator.pipeline if a.name == "attack"), None)
        eval_agent = next((a for a in orchestrator.pipeline if isinstance(a, EvaluationAgent)), None)

        # Ignore les alertes du recon / enum avant les cycles d'évasion.
        if eval_agent is not None:
            eval_agent.baseline_ids(eve_log)

        convergence: list[dict[str, Any]] = []
        total_detected = 0

        try:
            for i in range(1, cycles + 1):
                orchestrator._write_run_state(
                    orchestrator._run_state("evasion", "running", cycle=i, cycles=cycles))
                live.push_agent_event("cycle", f"{i}/{cycles}")
                evasion_result = evasion_agent.run(dry_run=dry_run) if evasion_agent else {}

                # Ne compter que les alertes *de ce cycle* (pas l'historique).
                if eval_agent is not None:
                    eval_agent.baseline_ids(eve_log)

                if attack_agent:
                    attack_agent.run(dry_run=dry_run)
                eval_result = (
                    eval_agent.run(dry_run=dry_run, eve_log=eve_log) if eval_agent else {}
                )

                detected = bool(eval_result.get("detected", False))
                rf_proba = float(eval_result.get("rf_proba") or 0.0)
                suricata_detected = bool(eval_result.get("suricata_detected", False))

                if evasion_agent:
                    learn_result = evasion_agent.learn(detected, p_detect=rf_proba)
                    reward = learn_result["reward"]
                    epsilon = evasion_agent.learner.epsilon
                else:
                    reward, epsilon = 0.0, 0.0

                if detected:
                    total_detected += 1
                det_rate = total_detected / i

                row = {
                    "cycle": i,
                    "detected": detected,
                    "reward": reward,
                    "detection_rate": round(det_rate, 4),
                    "epsilon": round(epsilon, 4),
                    "suricata_detected": suricata_detected,
                    "rf_proba": round(rf_proba, 4),
                    "rf_detected": bool(eval_result.get("rf_detected", False)),
                    "alert_count": int(eval_result.get("alert_count") or 0),
                    "action": evasion_result.get("action"),
                }
                convergence.append(row)

                orchestrator._write_state("evasion_state.json", {
                    "cycle": i,
                    "cycles": cycles,
                    "epsilon": round(epsilon, 4),
                    "last_action": evasion_result.get("action"),
                    "alerts": eval_result.get("alert_count", 0),
                    "p_detect": rf_proba,
                    "detected": detected,
                    "suricata_detected": suricata_detected,
                    "rf_detected": bool(eval_result.get("rf_detected", False)),
                    "reward": reward,
                    "detection_rate": round(det_rate, 4),
                })
                orchestrator._write_ptt_state()

                live.update_cycle(
                    cycle=i,
                    action=evasion_result.get("action"),
                    epsilon=epsilon,
                    detection_rate=det_rate,
                    rf_proba=rf_proba,
                    alert_count=int(eval_result.get("alert_count") or 0),
                    detected=detected,
                    reward=reward,
                    ports=ports,
                    vulns=vulns,
                    suricata_detected=suricata_detected,
                )

                if not live.enabled and (i <= 3 or i % 10 == 0 or i == cycles):
                    print(
                        f"  {i:<8} {_fmt_detected(detected):<19} "
                        f"{_fmt_reward(reward):<19} {epsilon:<10.4f} "
                        f"{det_rate:<12.1%}"
                    )
        finally:
            live.stop()

        # Tableau final + débrief (le live transient a déjà été effacé).
        _print_cycle_table(
            convergence,
            title="📊 Historique des cycles",
        )

        final_rate = total_detected / cycles if cycles > 0 else 0.0
        stealth_cycles = sum(1 for r in convergence if not r["detected"])
        print_result_box("Résultats de l'apprentissage", {
            "Cycles complétés": cycles,
            "Taux de détection final": f"{final_rate:.1%}",
            "Total détections": f"{total_detected}/{cycles}",
            "Cycles furtifs (NON)": f"{stealth_cycles}/{cycles}",
            "Epsilon final": f"{convergence[-1]['epsilon']:.4f}" if convergence else "?",
        })

        if convergence:
            first_rate = convergence[0]["detection_rate"]
            last_rate = convergence[-1]["detection_rate"]
            suri_hits = sum(1 for r in convergence if r.get("suricata_detected"))
            rf_hits = sum(1 for r in convergence if r.get("rf_detected"))
            print(f"  {Color.CYAN}Débrief signaux{Color.RESET}")
            print(f"  • Suricata a alerté sur {suri_hits}/{cycles} cycles")
            print(f"  • RF ≥ seuil sur {rf_hits}/{cycles} cycles")
            if stealth_cycles:
                print(
                    f"  {Color.GREEN}✓ {stealth_cycles} cycle(s) sans détection "
                    f"(Suricata silencieux ET RF sous seuil).{Color.RESET}"
                )
            if last_rate < first_rate:
                delta = (first_rate - last_rate) * 100
                print(
                    f"  {Color.GREEN}↓ Détection réduite de {first_rate:.0%} → "
                    f"{last_rate:.0%} (−{delta:.0f} pts) grâce à l'évasion apprise."
                    f"{Color.RESET}\n"
                )
            elif last_rate > first_rate:
                print(
                    f"  {Color.AMBER}↑ Détection {first_rate:.0%} → {last_rate:.0%} "
                    f"— l'agent explore encore (ε={convergence[-1]['epsilon']:.3f})."
                    f"{Color.RESET}\n"
                )
            else:
                print(
                    f"  {Color.DIM}Taux de détection stable à {last_rate:.0%} "
                    f"sur {cycles} cycles.{Color.RESET}\n"
                )

        orchestrator._write_run_state(
            orchestrator._run_state("orchestrator", "complete", cycles=cycles))
        orchestrator._write_ptt_state()
        return {"convergence": convergence, "final_detection_rate": final_rate}
