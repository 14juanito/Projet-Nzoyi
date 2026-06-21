"""Built-in validation tests for `python main.py --test`."""

from __future__ import annotations

from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.rl.qlearning import EvasionAction, EvasionQLearner, EvasionState


def test_ptt_shared_memory() -> bool:
    ptt = PentestTree("192.168.100.11")
    node = ptt.add("recon", "port_scan", {"open_ports": [22, 80]})
    found = ptt.find(kind="port_scan")
    duplicate_ok = False
    try:
        ptt.add("recon", "port_scan", {"open_ports": [22, 80]})
    except ValueError:
        duplicate_ok = True

    return (
        node.node_id == "ptt-0001"
        and len(found) == 1
        and found[0].data["open_ports"] == [22, 80]
        and duplicate_ok
    )


def test_qlearning_update() -> bool:
    learner = EvasionQLearner(alpha=0.5, gamma=0.0, epsilon=0.0)
    state = EvasionState(timing=4, delay_bucket=0, fragment=0)
    action = EvasionAction("slow_down", timing_delta=-1, delay_delta=1)
    next_state = learner.apply_action(state, action)
    learner.update(state, action, reward=1.0, next_state=next_state)

    return (
        learner.iterations == 1
        and learner.q_table[(state.as_key(), action.name)] == 0.5
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


def run_all_tests() -> dict[str, bool]:
    return {
        "PTT shared memory": test_ptt_shared_memory(),
        "Q-Learning update cycle": test_qlearning_update(),
        "Orchestrator 7-agent pipeline": test_orchestrator_pipeline(),
        "Stealth profile configuration": test_stealth_profile(),
    }
