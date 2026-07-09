"""Built-in validation tests for `python main.py --test`."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.agents.recon import ReconAgent, SIMULATED_PORTS
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.rl.qlearning import EvasionAction, EvasionQLearner, EvasionState
from nzoyi.tools.ids_log_reader import SuricataLogReader
from nzoyi.tools.nmap_wrapper import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


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


def test_orchestrator_pipeline() -> bool:
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"))
    report = orchestrator.run(dry_run=True)
    agents = report["agents"]

    expected = {"recon", "enumerator", "vulnerability", "evasion", "attack", "evaluation"}
    return expected.issubset(agents.keys()) and report["ptt"]["node_count"] >= 7


def test_stealth_profile() -> bool:
    profile = load_profile("stealth")
    return (
        profile.nmap_timing == "T2"
        and profile.scan_delay_ms == 500
        and profile.packet_fragment is True
        and profile.max_parallel == 2
    )


def test_recon_agent_dry_run() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = ReconAgent(ptt, load_profile("stealth"))
    result = agent.run(dry_run=True)
    return result["open_ports"] == SIMULATED_PORTS and result["dry_run"] is True


def test_nmap_wrapper_cli_parse() -> bool:
    results = parse_nmap_xml(str(FIXTURES / "nmap_sample.xml"))
    open_ports = [r["port"] for r in results if r["state"] == "open"]
    return open_ports == [22, 80] and results[0]["service"] == "ssh"


def test_suricata_log_reader() -> bool:
    # Generate a fresh EVE fixture so the time-window filter is deterministic
    # regardless of the current date.
    now = datetime.now(timezone.utc)
    events = [
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "alert",
            "src_ip": "192.168.100.10",
            "dest_ip": "192.168.100.11",
            "src_port": 54321,
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Nmap Scripting Engine User-Agent",
                "signature_id": 2012888,
                "severity": 2,
                "category": "Potentially Bad Traffic",
            },
        },
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
    tmp = FIXTURES / "eve_generated.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

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


def test_full_pipeline_dry_run() -> bool:
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"))
    report = orchestrator.run(dry_run=True)
    return (
        report["agents"]["recon"]["dry_run"] is True
        and report["agents"]["evaluation"]["detected"] is False
        and report["ptt"]["node_count"] >= 7
    )


def run_all_tests() -> dict[str, bool]:
    return {
        "PTT shared memory": test_ptt_shared_memory(),
        "Q-Learning update cycle": test_qlearning_update(),
        "Orchestrator 7-agent pipeline": test_orchestrator_pipeline(),
        "Stealth profile configuration": test_stealth_profile(),
        "Recon agent dry-run": test_recon_agent_dry_run(),
        "Nmap XML parser": test_nmap_wrapper_cli_parse(),
        "Suricata log reader": test_suricata_log_reader(),
        "Q-Learning epsilon decay": test_qlearning_convergence(),
        "Q-Learning save/load": test_qlearning_save_load(),
        "PTT thread safety": test_ptt_thread_safety(),
        "Full pipeline dry-run": test_full_pipeline_dry_run(),
    }
