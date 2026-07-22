"""Tests de validation pour `python main.py --test` (et pytest).

Toute dépendance réelle (Nmap, service RF, Suricata) est mockée : aucun test
ne dépend d'un réseau, d'un modèle scikit-learn sérialisé ou d'un service
distant réellement disponible.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from nzoyi.agents.attack import AttackAgent
from nzoyi.agents.enumerator import EnumeratorAgent
from nzoyi.agents.evaluation import EvaluationAgent
from nzoyi.agents.evasion import EvasionAgent
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.agents.recon import ReconAgent
from nzoyi.agents.vulnerability import VulnerabilityAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.llm.orchestrator_llm import LLMOrchestrator
from nzoyi.rl.qlearning import EvasionAction, EvasionQLearner, EvasionState
from nzoyi.tools.ids_log_reader import SuricataLogReader
from nzoyi.tools.nmap_wrapper import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _write_eve_fixture(name: str, events: list[dict]) -> Path:
    path = FIXTURES / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    return path


def _alert_event(now: datetime, signature: str = "ET SCAN Nmap Scripting Engine") -> dict:
    return {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": "192.168.100.10",
        "dest_ip": "192.168.100.11",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": signature,
            "signature_id": 2012888,
            "severity": 2,
            "category": "Potentially Bad Traffic",
        },
    }


# ── PTT / Q-Learning (inchangés — pas de dépendance externe) ────────────────

def test_ptt_shared_memory() -> bool:
    ptt = PentestTree("192.168.100.11")
    node = ptt.add("recon", "port_scan", {"open_ports": [22, 80]})
    found = ptt.find(kind="port_scan")
    duplicate_ok = False
    try:
        ptt.add("recon", "port_scan", {"open_ports": [22, 80]})
    except ValueError:
        duplicate_ok = True

    ptt.set_recon_results([{"port": 22}])
    return (
        node.node_id == "ptt-0001"
        and len(found) == 1
        and found[0].data["open_ports"] == [22, 80]
        and duplicate_ok
        and ptt.get_recon_results() == [{"port": 22}]
    )


def test_qlearning_update() -> bool:
    learner = EvasionQLearner(alpha=0.5, gamma=0.0, epsilon=0.2, epsilon_decay=1.0)
    state = EvasionState(timing=4, delay_bucket=0, fragment=0)
    action = EvasionAction("slow_down", timing_delta=-1, delay_delta=1)
    next_state = learner.apply_action(state, action)
    learner.update(state, action, reward=1.0, next_state=next_state)

    key = learner._q_key(state, action.name)
    return (
        learner.iterations == 1
        and learner.q_table[key] == 0.5
        and next_state.timing == 3
        and next_state.delay_bucket == 1
    )


def test_stealth_profile() -> bool:
    profile = load_profile("stealth")
    return (
        profile.nmap_timing == "T2"
        and profile.scan_delay_ms == 500
        and profile.packet_fragment is True
        and profile.max_parallel == 2
    )


def test_nmap_wrapper_cli_parse() -> bool:
    results = parse_nmap_xml(str(FIXTURES / "nmap_sample.xml"))
    open_ports = [r["port"] for r in results if r["state"] == "open"]
    return open_ports == [22, 80] and results[0]["service"] == "ssh"


def test_suricata_log_reader() -> bool:
    now = datetime.now(timezone.utc)
    events = [
        _alert_event(now, "ET SCAN Nmap Scripting Engine User-Agent"),
        {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
         "event_type": "flow", "src_ip": "192.168.100.10", "dest_ip": "192.168.100.11"},
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "alert",
            "src_ip": "192.168.100.10",
            "dest_ip": "192.168.100.11",
            "src_port": 54322,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "signature_id": 2100498,
                "severity": 1,
                "category": "Potentially Compromised Host",
            },
        },
    ]
    tmp = _write_eve_fixture("eve_generated.json", events)
    try:
        reader = SuricataLogReader(str(tmp))
        alerts = reader.get_recent_alerts(seconds=300, source_ip="192.168.100.10")
    finally:
        tmp.unlink(missing_ok=True)

    return len(alerts) == 2 and alerts[0]["signature_id"] == 2012888


def test_qlearning_convergence() -> bool:
    learner = EvasionQLearner(epsilon=0.5, epsilon_decay=0.995, epsilon_min=0.05)
    state = EvasionState(timing=3, delay_bucket=2, fragment=1)
    action = EvasionAction("hold")
    for _ in range(50):
        learner.update(state, action, 1.0, state)
    return learner.epsilon < 0.5 and learner.epsilon >= 0.05


def test_qlearning_save_load() -> bool:
    learner = EvasionQLearner()
    state = EvasionState(1, 2, 0)
    action = EvasionAction("hold")
    learner.update(state, action, 1.0, state)

    path = Path("results/test_qtable.json")
    path.parent.mkdir(exist_ok=True)
    learner.save(path)
    loaded = EvasionQLearner.load(path)
    path.unlink(missing_ok=True)
    return loaded.iterations == 1 and loaded.q_table == learner.q_table


def test_ptt_thread_safety() -> bool:
    ptt = PentestTree("192.168.100.11")
    errors: list[str] = []

    def worker(i: int) -> None:
        try:
            ptt.add_vulnerability({"id": i})
            ptt.record_evaluation(i % 2 == 0, {})
            ptt.set_recon_results([{"port": i}])
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return not errors and len(ptt.get_vulnerabilities()) == 20


# ── Recon (mock NmapWrapper) ─────────────────────────────────────────────

def test_recon_agent_real_scan() -> bool:
    fake_ports = [
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "8.9", "protocol": "tcp"},
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache", "version": "2.4.52", "protocol": "tcp"},
        {"host": "192.168.100.11", "port": 9999, "state": "closed", "service": "",
         "product": "", "version": "", "protocol": "tcp"},
    ]
    ptt = PentestTree("192.168.100.11")
    agent = ReconAgent(ptt, load_profile("stealth"))
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=fake_ports):
        result = agent.run(dry_run=False)

    stored = ptt.get_recon_results()
    return (
        result["open_ports"] == [22, 80]
        and len(stored) == 2
        and stored[0]["service"] == "ssh"
        and stored[0]["version"] == "8.9"
    )


def test_recon_agent_nmap_unavailable() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = ReconAgent(ptt, load_profile("stealth"))
    with patch(
        "nzoyi.tools.nmap_wrapper.NmapWrapper.scan",
        side_effect=FileNotFoundError("nmap not installed"),
    ):
        result = agent.run(dry_run=False)
    return result["open_ports"] == [] and ptt.get_recon_results() == []


# ── Enumerator (mock banner grab) ────────────────────────────────────────

def test_enumerator_agent_banner_grab() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh",
         "product": "", "version": ""},
    ])
    agent = EnumeratorAgent(ptt, load_profile("stealth"))
    with patch.object(EnumeratorAgent, "_grab_banner", return_value="SSH-2.0-OpenSSH_8.9"):
        result = agent.run(dry_run=False)

    stored = result["service_list"]
    return (
        len(stored) == 1
        and stored[0]["name"] == "ssh"
        and stored[0]["product"] == "SSH-2.0-OpenSSH_8.9"
        and stored[0]["banner"] == "SSH-2.0-OpenSSH_8.9"
    )


def test_enumerator_agent_unknown_service() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 31337, "state": "open", "service": "",
         "product": "", "version": ""},
    ])
    agent = EnumeratorAgent(ptt, load_profile("stealth"))
    with patch.object(EnumeratorAgent, "_grab_banner", return_value=""):
        result = agent.run(dry_run=False)
    stored = result["service_list"]
    return len(stored) == 1 and stored[0]["name"] == "unknown" and stored[0]["banner"] == ""


# ── Vulnerability (corrélation CVE locale, pas de mock nécessaire) ──────────

def test_vulnerability_agent_correlation() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache", "version": "2.4.49"},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"))
    result = agent.run(dry_run=False)
    cve_ids = {f["cve_id"] for f in result["findings"]}
    return "CVE-2021-41773" in cve_ids and len(ptt.get_vulnerabilities()) >= 1


def test_vulnerability_agent_no_match() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 8080, "state": "open", "service": "unknown",
         "product": "", "version": ""},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"))
    result = agent.run(dry_run=False)
    return result["findings"] == [] and ptt.get_vulnerabilities() == []


def test_vulnerability_agent_fallback_to_enumeration() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.add("enumerator", "service_enum", {
        "service_list": [
            {"port": 21, "name": "ftp", "product": "vsftpd", "version": "2.3.4", "banner": ""},
        ],
        "services": {},
        "dry_run": False,
    })
    agent = VulnerabilityAgent(ptt, load_profile("stealth"))
    result = agent.run(dry_run=False)
    cve_ids = {f["cve_id"] for f in result["findings"]}
    return "CVE-2011-2523" in cve_ids


# ── Evasion (mock RFOracle) ──────────────────────────────────────────────

def test_evasion_agent_oracle_unavailable() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = EvasionAgent(ptt, load_profile("stealth"), learner=EvasionQLearner(epsilon=0.0))
    no_oracle = agent.oracle is None
    result = agent.run(dry_run=False)
    return no_oracle and result["detected"] is False and result["p_detect"] == 0.0


def test_evasion_agent_with_mocked_oracle() -> bool:
    ptt = PentestTree("192.168.100.11")
    fake_oracle = MagicMock()
    fake_oracle.predict_p_detect.return_value = 0.9
    agent = EvasionAgent(
        ptt, load_profile("stealth"), learner=EvasionQLearner(epsilon=0.0), oracle=fake_oracle
    )
    result = agent.run(dry_run=False)
    return result["p_detect"] == 0.9 and result["detected"] is True


# ── Attack (mock NmapWrapper, vérifie le mode plan) ─────────────────────

def test_attack_agent_dry_run_plan() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([{"host": "192.168.100.11", "port": 80, "state": "open", "service": "http"}])
    agent = AttackAgent(ptt, load_profile("stealth"))
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan") as mock_scan:
        result = agent.run(dry_run=True)
        not_called = not mock_scan.called

    attempts = ptt.to_dict()["attack_attempts"]
    return (
        not_called
        and result["executed"] is False
        and len(attempts) == 1
        and attempts[0]["dry_run"] is True
    )


def test_attack_agent_real_execution() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh"},
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http"},
    ])
    agent = AttackAgent(ptt, load_profile("stealth"))
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=[]) as mock_scan:
        result = agent.run(dry_run=False)

    attempts = ptt.to_dict()["attack_attempts"]
    return (
        mock_scan.call_count == 1
        and result["executed"] is True
        and len(attempts) == 2
        and all(a["executed"] for a in attempts)
    )


def test_attack_agent_no_ports_no_execution() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = AttackAgent(ptt, load_profile("stealth"))
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan") as mock_scan:
        result = agent.run(dry_run=False)
    return not mock_scan.called and result["executed"] is False and result["attempts"] == []


# ── Evaluation (mock SuricataLogReader via fixture + mock RFClient) ────────

def test_evaluation_agent_fusion() -> bool:
    now = datetime.now(timezone.utc)
    tmp = _write_eve_fixture("eve_eval_generated.json", [_alert_event(now)])

    try:
        ptt = PentestTree("192.168.100.11")
        agent = EvaluationAgent(ptt, load_profile("stealth"), attacker_ip="192.168.100.10")
        agent.rf_client.predict = lambda features: {"label": 1, "proba": 0.87}
        result = agent.run(dry_run=False, eve_log=str(tmp))
    finally:
        tmp.unlink(missing_ok=True)

    sub_signals = ptt.to_dict()["evaluations"][-1]["alert_details"]
    return (
        result["suricata_detected"] is True
        and result["rf_detected"] is True
        and result["detected"] is True
        and result["rf_proba"] == 0.87
        and sub_signals["suricata_detected"] is True
        and sub_signals["rf_detected"] is True
    )


def test_evaluation_agent_unavailable() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = EvaluationAgent(ptt, load_profile("stealth"))
    agent.rf_client.predict = lambda features: None
    result = agent.run(dry_run=False, eve_log="/nonexistent/eve.json")
    return (
        result["suricata_detected"] is False
        and result["rf_detected"] is False
        and result["detected"] is False
        and result["source"] == "unavailable"
    )


# ── Pipeline complet orchestré (mocks NmapWrapper + RFClient) ──────────────

def test_orchestrator_pipeline() -> bool:
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=False)

    fake_ports = [
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "8.9", "protocol": "tcp"},
    ]

    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=fake_ports), \
         patch("nzoyi.tools.rf_client.RFClient.predict", return_value={"label": 0, "proba": 0.1}):
        report = orchestrator.run(dry_run=False)

    agents = report["agents"]
    expected = {"recon", "enumerator", "vulnerability", "evasion", "attack", "evaluation"}
    return (
        expected.issubset(agents.keys())
        and report["ptt"]["node_count"] >= 7
        and len(ptt.find(kind="llm_strategy")) == 1
        and len(ptt.find(kind="llm_replan")) == 1
    )


def test_full_pipeline_dry_run_plan_mode() -> bool:
    """dry_run n'affecte QUE AttackAgent (mode plan) — recon scanne toujours réellement."""
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=False)
    fake_ports = [
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "8.9", "protocol": "tcp"},
    ]

    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=fake_ports) as mock_scan, \
         patch("nzoyi.tools.rf_client.RFClient.predict", return_value=None):
        report = orchestrator.run(dry_run=True)

    return (
        mock_scan.call_count == 1  # un seul appel: recon (attack reste en mode plan)
        and report["agents"]["attack"]["executed"] is False
        and report["agents"]["attack"]["dry_run"] is True
    )


def test_full_pipeline_online_signals() -> bool:
    """Vérifie que le pipeline online produit bien deux sous-signaux distincts (H2)."""
    now = datetime.now(timezone.utc)
    tmp = _write_eve_fixture("eve_pipeline_generated.json", [_alert_event(now)])
    fake_ports = [
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache", "version": "2.4.49", "protocol": "tcp"},
    ]

    try:
        ptt = PentestTree("192.168.100.11")
        orchestrator = OrchestratorAgent(
            ptt, load_profile("stealth"), eve_log=str(tmp), attacker_ip="192.168.100.10", use_llm=False,
        )
        with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=fake_ports), \
             patch("nzoyi.tools.rf_client.RFClient.predict", return_value={"label": 1, "proba": 0.77}):
            report = orchestrator.run(dry_run=False)
    finally:
        tmp.unlink(missing_ok=True)

    eval_result = report["agents"]["evaluation"]
    return (
        eval_result["suricata_detected"] is True
        and eval_result["rf_detected"] is True
        and eval_result["rf_proba"] == 0.77
        and eval_result["detected"] is True
    )


# ── Couche stratégique LLM (sanitize + gating de la boucle d'évasion) ──────

def test_llm_orchestrator_sanitize_clamps_and_validates() -> bool:
    """_sanitize doit clamper `cycles` hors bornes et rejeter un profil invalide."""
    too_high = LLMOrchestrator._sanitize({
        "profil": "profil-inexistant",
        "cycles": 9999,
    })
    too_low = LLMOrchestrator._sanitize({"cycles": 1})
    valid = LLMOrchestrator._sanitize({
        "profil": "aggressive",
        "ports_cibles": ["80", 443],
        "services_focus": ["http"],
        "lancer_boucle_evasion": False,
        "cycles": 42,
        "raison": "test",
    })
    return (
        too_high["profil"] == "stealth"  # profil invalide -> repli
        and too_high["cycles"] == 500  # clampé au maximum
        and too_low["cycles"] == 10  # clampé au minimum
        and valid["profil"] == "aggressive"
        and valid["ports_cibles"] == [80, 443]
        and valid["lancer_boucle_evasion"] is False
        and valid["cycles"] == 42
    )


def test_llm_orchestrator_fallback_schema() -> bool:
    """Le repli hors-ligne doit respecter le schéma complet attendu par l'orchestrateur."""
    planner = LLMOrchestrator(enabled=False)
    plan = planner.decide({"target": "192.168.100.11"})
    return (
        plan["profil"] == "stealth"
        and plan["ports_cibles"] == [22, 80, 21]
        and plan["services_focus"] == []
        and plan["lancer_boucle_evasion"] is True
        and plan["cycles"] == 100
        and isinstance(plan["raison"], str)
    )


def test_learning_loop_aborted_by_llm() -> bool:
    """lancer_boucle_evasion=False doit sauter la boucle Q-Learning entièrement."""
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=False)
    aborted_plan = {
        "profil": "stealth",
        "ports_cibles": [22],
        "services_focus": [],
        "lancer_boucle_evasion": False,
        "cycles": 50,
        "raison": "cible jugée non prioritaire",
    }
    fake_ports = [
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh"},
    ]

    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=fake_ports) as mock_scan, \
         patch.object(OrchestratorAgent, "_strategic_replan", return_value=aborted_plan):
        result = orchestrator.learning_loop(dry_run=True)

    return (
        result["cycles"] == 0
        and result["convergence"] == []
        and mock_scan.call_count == 1  # seul recon a scanné, pas la boucle évasion/attaque
        and len(ptt.find(kind="evasion_aborted")) == 1
        and ptt.find(kind="evasion_aborted")[0].data["raison"] == "cible jugée non prioritaire"
    )


def run_all_tests() -> dict[str, bool]:
    return {
        "PTT shared memory": test_ptt_shared_memory(),
        "Q-Learning update cycle": test_qlearning_update(),
        "Stealth profile configuration": test_stealth_profile(),
        "Nmap XML parser": test_nmap_wrapper_cli_parse(),
        "Suricata log reader": test_suricata_log_reader(),
        "Q-Learning epsilon decay": test_qlearning_convergence(),
        "Q-Learning save/load": test_qlearning_save_load(),
        "PTT thread safety": test_ptt_thread_safety(),
        "Recon agent — scan réel (mocké)": test_recon_agent_real_scan(),
        "Recon agent — nmap indisponible": test_recon_agent_nmap_unavailable(),
        "Enumerator — banner grab": test_enumerator_agent_banner_grab(),
        "Enumerator — service inconnu": test_enumerator_agent_unknown_service(),
        "Vulnerability — corrélation CVE": test_vulnerability_agent_correlation(),
        "Vulnerability — aucune correspondance": test_vulnerability_agent_no_match(),
        "Vulnerability — repli sur énumération": test_vulnerability_agent_fallback_to_enumeration(),
        "Evasion — oracle RF indisponible": test_evasion_agent_oracle_unavailable(),
        "Evasion — oracle RF mocké": test_evasion_agent_with_mocked_oracle(),
        "Attack — mode plan (dry-run)": test_attack_agent_dry_run_plan(),
        "Attack — exécution réelle (mockée)": test_attack_agent_real_execution(),
        "Attack — aucun port, aucune exécution": test_attack_agent_no_ports_no_execution(),
        "Evaluation — fusion Suricata + RF": test_evaluation_agent_fusion(),
        "Evaluation — signaux indisponibles": test_evaluation_agent_unavailable(),
        "Orchestrator 7-agent pipeline": test_orchestrator_pipeline(),
        "Pipeline complet — mode plan dry-run": test_full_pipeline_dry_run_plan_mode(),
        "Pipeline complet — signaux online distincts": test_full_pipeline_online_signals(),
        "LLM stratégique — sanitize clamp/validation": test_llm_orchestrator_sanitize_clamps_and_validates(),
        "LLM stratégique — schéma du repli hors-ligne": test_llm_orchestrator_fallback_schema(),
        "Boucle d'évasion avortée par le LLM": test_learning_loop_aborted_by_llm(),
    }
