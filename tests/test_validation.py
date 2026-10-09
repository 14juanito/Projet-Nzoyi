"""Tests de validation pour `python main.py --test` (et pytest).

Toute dépendance réelle (Nmap, service RF, Suricata) est mockée : aucun test
ne dépend d'un réseau, d'un modèle scikit-learn sérialisé ou d'un service
distant réellement disponible.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from nzoyi.agents.attack import AttackAgent
from nzoyi.agents.enumerator import EnumeratorAgent
from nzoyi.agents.evaluation import EvaluationAgent
from nzoyi.agents.evasion import EvasionAgent
from nzoyi.agents.orchestrator import OrchestratorAgent
from nzoyi.agents.recon import ReconAgent
from nzoyi.agents.vulnerability import VulnerabilityAgent
from nzoyi.core.config import load_profile
from nzoyi.core.ptt import PentestTree
from nzoyi.llm.attack_priority_llm import AttackPriorityLLM
from nzoyi.llm.backend import LLMBackend, LLMBackendError
from nzoyi.llm.backends.anthropic_backend import AnthropicBackend
from nzoyi.llm.backends.openai_compat_backend import OpenAICompatibleBackend
from nzoyi.llm.evaluation_rationale_llm import EvaluationRationaleLLM
from nzoyi.llm.json_utils import strip_markdown_fences
from nzoyi.llm.orchestrator_llm import LLMOrchestrator
from nzoyi.llm.vuln_triage_llm import VulnTriageLLM
from nzoyi.rl.qlearning import EvasionAction, EvasionQLearner, EvasionState
from nzoyi.tools.ids_log_reader import SuricataLogReader
from nzoyi.tools.ids_reconciliation import reconcile
from nzoyi.tools.nmap_wrapper import parse_nmap_xml
from run_j7_campaign import check_clock_skew

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


def test_evasion_state_as_key_includes_target_signature() -> bool:
    """Garde-fou J7 : as_key() doit inclure target_signature (4-uplet), pas
    seulement (timing, delay_bucket, fragment) — sinon le Q-learning ne
    distingue plus les contextes de cible, même si la seed diverge bien."""
    state_a = EvasionState(timing=2, delay_bucket=1, fragment=0, target_signature=111)
    state_b = EvasionState(timing=2, delay_bucket=1, fragment=0, target_signature=222)
    key_a, key_b = state_a.as_key(), state_b.as_key()
    return (
        len(key_a) == 4
        and key_a[3] == 111
        and key_b[3] == 222
        and key_a != key_b
    )


def test_strip_markdown_fences_json_language_tag() -> bool:
    """Fences ```json ... ``` (cas Claude/J7-ter) — doivent être retirées."""
    raw = '```json\n{"a": 1}\n```'
    return strip_markdown_fences(raw) == '{"a": 1}'


def test_strip_markdown_fences_bare() -> bool:
    """Fences nues ``` ... ``` (sans identifiant de langage)."""
    raw = '```\n{"a": 1}\n```'
    return strip_markdown_fences(raw) == '{"a": 1}'


def test_strip_markdown_fences_absent_unchanged() -> bool:
    """Réponse sans fences — doit rester inchangée (hors strip() des bords)."""
    raw = '{"a": 1}'
    return strip_markdown_fences(raw) == '{"a": 1}'


def test_strip_markdown_fences_surrounding_whitespace() -> bool:
    """Espaces/retours à la ligne superflus avant/après les fences."""
    raw = '\n\n  ```json\n{"a": 1}\n```  \n\n'
    return strip_markdown_fences(raw) == '{"a": 1}'


def test_ids_reconciliation_reattributes_late_arriving_alert() -> bool:
    """Cas identifié en J7-ter : une alerte réelle, timestampée DANS la
    fenêtre du cycle 1 (avant la lecture du cycle 1), doit être réattribuée
    au cycle 1 par reconcile() — jamais perdue, et jamais comptée sur le
    cycle 2 — même si elle n'a jamais été vue par la lecture live de ce
    cycle (c'est exactement le bug corrigé : son arrivée tardive sur le
    mirror SSH local l'avait fait passer entre deux lectures)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        ptt_path = tmp_path / "ptt.json"
        ptt_path.write_text(json.dumps({
            "nodes": [
                {
                    "kind": "ids_feedback",
                    "timestamp": "2026-01-01T00:00:10+00:00",
                    "data": {"alert_count": 0, "detected": False, "rf_detected": False},
                },
                {
                    "kind": "ids_feedback",
                    "timestamp": "2026-01-01T00:00:20+00:00",
                    "data": {"alert_count": 0, "detected": False, "rf_detected": False},
                },
            ]
        }), encoding="utf-8")

        mirror_path = tmp_path / "eve.json"
        mirror_path.write_text("\n".join([
            json.dumps({
                "event_type": "alert", "timestamp": "2026-01-01T00:00:01+00:00",
                "src_ip": "192.168.100.10", "dest_ip": "192.168.100.14",
                "alert": {"signature": "SURICATA Ethertype unknown"},
            }),
            # Alerte réelle du cycle 1 (timestamp Suricata 00:00:09, DANS la
            # fenêtre (None, 00:00:10]) — jamais comptée en direct (c'est le
            # bug), mais doit être réattribuée ici au cycle 1.
            json.dumps({
                "event_type": "alert", "timestamp": "2026-01-01T00:00:09+00:00",
                "src_ip": "192.168.100.10", "dest_ip": "192.168.100.14",
                "alert": {"signature": "ET SCAN Potential SSH Scan"},
            }),
        ]) + "\n", encoding="utf-8")

        result = reconcile(ptt_path, mirror_path)
        cycles = result["cycles"]
        return (
            result["n"] == 2
            and cycles[0].corrected_alert_count == 1
            and cycles[0].corrected_detected is True
            and cycles[0].original_alert_count == 0
            and cycles[1].corrected_alert_count == 0
            and cycles[1].corrected_detected is False
            and result["alerts_reattributed"] == 1
            and result["original_detection_rate"] == 0.0
            and result["corrected_detection_rate"] == 0.5
        )


def test_ids_reconciliation_cycle1_not_contaminated_by_earlier_backend() -> bool:
    """Le mirror eve.json est continu sur toute une campagne (plusieurs
    backends qui s'enchaînent, jamais recréé entre deux) : la fenêtre du
    cycle 1 doit être bornée par le premier evasion_step de CE backend, pas
    laissée ouverte vers le passé — sinon elle capterait, à tort, les
    alertes d'un backend précédent exécuté plus tôt dans le même mirror."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        ptt_path = tmp_path / "ptt.json"
        ptt_path.write_text(json.dumps({
            "nodes": [
                # Backend précédent (non modélisé ici, juste son empreinte
                # temporelle dans le mirror partagé) : voir l'alerte à
                # 00:00:00 dans le mirror ci-dessous, largement AVANT ce
                # backend. evasion_step marque le début réel du cycle 1 de
                # CE backend.
                {"kind": "evasion_step", "timestamp": "2026-01-01T00:01:00+00:00", "data": {}},
                {
                    "kind": "ids_feedback",
                    "timestamp": "2026-01-01T00:01:10+00:00",
                    "data": {"alert_count": 0, "detected": False, "rf_detected": False},
                },
            ]
        }), encoding="utf-8")

        mirror_path = tmp_path / "eve.json"
        mirror_path.write_text("\n".join([
            # Alerte d'un backend ANTÉRIEUR — ne doit jamais compter pour
            # le cycle 1 de CE backend (hors de sa fenêtre réelle).
            json.dumps({
                "event_type": "alert", "timestamp": "2026-01-01T00:00:00+00:00",
                "src_ip": "192.168.100.10", "dest_ip": "192.168.100.14",
                "alert": {"signature": "ET SCAN Potential SSH Scan"},
            }),
        ]) + "\n", encoding="utf-8")

        result = reconcile(ptt_path, mirror_path)
        return (
            result["n"] == 1
            and result["cycles"][0].corrected_alert_count == 0
            and result["cycles"][0].corrected_detected is False
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


def test_suricata_cursor_baseline_ignores_history() -> bool:
    """Après seek_end(), seules les alertes *nouvelles* comptent (évite 100% faux)."""
    now = datetime.now(timezone.utc)
    tmp = _write_eve_fixture("eve_baseline.json", [_alert_event(now, "OLD ALERT")])
    try:
        reader = SuricataLogReader(str(tmp))
        reader.seek_end()
        # Ajoute une alerte après la baseline.
        with open(tmp, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(_alert_event(now, "NEW ALERT")) + "\n")
        alerts = reader.get_recent_alerts(
            source_ip="192.168.100.10", since_cursor_only=True
        )
    finally:
        tmp.unlink(missing_ok=True)
    return len(alerts) == 1 and alerts[0]["signature"] == "NEW ALERT"


def test_suricata_parses_plus0000_timestamp() -> bool:
    ts = SuricataLogReader._parse_timestamp("2026-08-12T04:15:56.480396+0000")
    return ts is not None and ts.year == 2026 and ts.tzinfo is not None


def test_suricata_ignores_decoder_noise() -> bool:
    """« SURICATA Ethertype unknown » ne doit pas compter comme détection IDS."""
    from nzoyi.tools.ids_log_reader import is_security_alert

    return (
        is_security_alert("ET SCAN Nmap Scripting Engine") is True
        and is_security_alert("SURICATA Ethertype unknown") is False
        and is_security_alert("GPL ATTACK_RESPONSE id check returned root") is True
    )


# ── Zeek+ML (AutoZeekWatch) log reader — IDS backend alternatif (J8) ───────


def _zeek_ml_line(ts: datetime, module: str, score: float, orig_p: int = 54321) -> str:
    """Construit une ligne au format réel produit par AutoZeekWatch/infer.py
    (logging standard, message = "<module>: <repr dict>")."""
    payload = {
        "uid": "Cabc123",
        "id.resp_h": "192.168.100.13",
        "id.orig_h": "192.168.100.10",
        "id.orig_p": orig_p,
        "id.resp_p": 22,
        "anomaly_score": score,
    }
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    return f"{stamp} - root - INFO - {module}: {payload!r}"


def _write_zeek_ml_fixture(name: str, lines: list[str]) -> Path:
    path = FIXTURES / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")
    return path


def test_zeek_ml_log_reader_threshold() -> bool:
    """Seules les anomalies au-dessus du seuil configuré sont retenues."""
    from nzoyi.tools.zeek_ml_log_reader import ZeekMLLogReader

    now = datetime.now(timezone.utc)
    lines = [
        _zeek_ml_line(now, "conn", score=0.2),  # sous le seuil, ignoré
        _zeek_ml_line(now, "conn", score=1.5),  # au-dessus, retenu
        "ligne corrompue non parsable",
    ]
    tmp = _write_zeek_ml_fixture("zeek_ml_generated.log", lines)
    try:
        reader = ZeekMLLogReader(str(tmp), score_threshold=1.0)
        alerts = reader.get_recent_alerts(source_ip="192.168.100.10", since_cursor_only=True)
    finally:
        tmp.unlink(missing_ok=True)
    return (
        len(alerts) == 1
        and alerts[0]["anomaly_score"] == 1.5
        and alerts[0]["category"] == "conn"
        and alerts[0]["src_ip"] == "192.168.100.10"
        and alerts[0]["dest_ip"] == "192.168.100.13"
    )


def test_zeek_ml_cursor_baseline_ignores_history() -> bool:
    """Après seek_end(), seules les anomalies *nouvelles* comptent."""
    from nzoyi.tools.zeek_ml_log_reader import ZeekMLLogReader

    now = datetime.now(timezone.utc)
    tmp = _write_zeek_ml_fixture(
        "zeek_ml_baseline.log", [_zeek_ml_line(now, "conn", score=5.0)]
    )
    try:
        reader = ZeekMLLogReader(str(tmp), score_threshold=1.0)
        reader.seek_end()
        with open(tmp, "a", encoding="utf-8") as handle:
            handle.write(_zeek_ml_line(now, "ssh", score=3.3) + "\n")
        alerts = reader.get_recent_alerts(
            source_ip="192.168.100.10", since_cursor_only=True
        )
    finally:
        tmp.unlink(missing_ok=True)
    return len(alerts) == 1 and alerts[0]["category"] == "ssh"


def test_zeek_ml_reader_missing_file_raises() -> bool:
    from nzoyi.tools.zeek_ml_log_reader import ZeekMLLogReader

    try:
        ZeekMLLogReader("/nonexistent/zeek_ml_anomalies.log")
        return False
    except FileNotFoundError:
        return True


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


def test_recon_agent_timing_decoupled_from_profile() -> bool:
    """Le recon initial doit toujours scanner en T4/timeout=600s, quel que soit le profil."""
    checks = []
    for profile_name in ("stealth", "aggressive"):
        ptt = PentestTree("192.168.100.11")
        agent = ReconAgent(ptt, load_profile(profile_name))
        with patch("nzoyi.agents.recon.NmapWrapper") as mock_wrapper_cls:
            mock_wrapper_cls.return_value.scan.return_value = []
            agent.run(dry_run=False)

        init_kwargs = mock_wrapper_cls.call_args.kwargs
        _, scan_kwargs = mock_wrapper_cls.return_value.scan.call_args
        checks.append(init_kwargs.get("timeout") == 600 and scan_kwargs.get("timing") == 4)
    return all(checks)


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


# ── Vulnerability (corrélation CVE locale + fingerprint DVWA) ──────────

def test_vulnerability_agent_correlation() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache", "version": "2.4.49"},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=None):
        result = agent.run(dry_run=False)
    cve_ids = {f["cve_id"] for f in result["findings"]}
    return "CVE-2021-41773" in cve_ids and len(ptt.get_vulnerabilities()) >= 1


def test_vulnerability_agent_apache_lab_version() -> bool:
    """Apache 2.4.25 (lab DVWA) doit matcher les CVE élargies, pas seulement 2.4.49."""
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache httpd", "version": "2.4.25"},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=None):
        result = agent.run(dry_run=False)
    cve_ids = {f["cve_id"] for f in result["findings"]}
    return "CVE-2017-9798" in cve_ids and "CVE-2017-3167" in cve_ids


def test_vulnerability_agent_dvwa_detection() -> bool:
    """DVWA détecté via fingerprint → findings SQLi/XSS/etc."""
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache httpd", "version": "2.4.25"},
    ])
    fake_dvwa = {
        "app": "DVWA",
        "url": "http://192.168.100.11:80/login.php",
        "port": 80,
        "status": 200,
        "evidence": ["cookie:security", "login.php", "title:DVWA"],
    }
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=fake_dvwa):
        result = agent.run(dry_run=False)
    ids = {f["cve_id"] for f in result["findings"]}
    return (
        result.get("dvwa", {}).get("app") == "DVWA"
        and "DVWA-SQLI" in ids
        and "DVWA-XSS-REFLECTED" in ids
        and "DVWA-CMD-INJECTION" in ids
        and any(f.get("source") == "app_fingerprint" for f in result["findings"])
    )


def test_vulnerability_agent_no_match() -> bool:
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 8080, "state": "open", "service": "unknown",
         "product": "", "version": ""},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=None):
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
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=None):
        result = agent.run(dry_run=False)
    cve_ids = {f["cve_id"] for f in result["findings"]}
    return "CVE-2011-2523" in cve_ids


# ── Evasion (mock RFOracle) ──────────────────────────────────────────────

def test_evasion_agent_oracle_unavailable() -> bool:
    ptt = PentestTree("192.168.100.11")
    with patch.object(EvasionAgent, "_load_oracle", return_value=None):
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
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=False)
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
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=False)
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
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan") as mock_scan:
        result = agent.run(dry_run=False)
    return not mock_scan.called and result["executed"] is False and result["attempts"] == []


def test_attack_agent_restricts_to_discovered_ports() -> bool:
    """Le scan d'attaque ne cible QUE les ports découverts par le recon (via -p)."""
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 22, "state": "open", "service": "ssh"},
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http"},
    ])
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=[]) as mock_scan:
        agent.run(dry_run=False)
    _, kwargs = mock_scan.call_args
    return kwargs.get("ports") == [22, 80]


def test_attack_agent_timeout_not_fatal() -> bool:
    """Un timeout d'attaque ne plante pas le cycle: résultat 'non abouti'."""
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http"},
    ])
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=False)
    with patch(
        "nzoyi.tools.nmap_wrapper.NmapWrapper.scan",
        side_effect=TimeoutError("Nmap scan timed out after 30s"),
    ):
        result = agent.run(dry_run=False)  # ne doit pas lever
    return (
        result["executed"] is False
        and result["timed_out"] is True
        and len(result["attempts"]) == 1
        and result["attempts"][0]["timed_out"] is True
    )


def test_attack_applies_evasion_strategy() -> bool:
    """L'attaque doit appliquer timing/delay/fragment issus du Q-Learning (PTT)."""
    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http"},
    ])
    ptt.update_evasion_strategy({"state": (1, 4, 1), "action": "slow_down"})
    agent = AttackAgent(ptt, load_profile("aggressive"), use_llm=False)  # profil bruyant volontairement
    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=[]) as mock_scan:
        result = agent.run(dry_run=False)
    _, kwargs = mock_scan.call_args
    return (
        kwargs.get("timing") == 1
        and kwargs.get("scan_delay_ms") == 400
        and kwargs.get("fragment") is True
        and result["timing"] == 1
    )


# ── Evaluation (mock SuricataLogReader via fixture + mock RFClient) ────────

def test_evaluation_agent_fusion() -> bool:
    now = datetime.now(timezone.utc)
    tmp = _write_eve_fixture("eve_eval_generated.json", [_alert_event(now)])

    try:
        ptt = PentestTree("192.168.100.11")
        agent = EvaluationAgent(ptt, load_profile("stealth"), attacker_ip="192.168.100.10", use_llm=False)
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


def test_check_clock_skew_detects_significant_drift() -> bool:
    """Garde-fou J7-ter : un décalage simulé de ~38 min (cas réel rencontré,
    VM cible jamais synchronisée NTP) doit être détecté et signalé."""
    import time as time_module

    local_now = time_module.time()
    remote_epoch = local_now + 38 * 60  # cible 38 min en avance, comme en J7-ter

    fake_proc = MagicMock(returncode=0, stdout=f"{remote_epoch:.6f}\n", stderr="")
    with patch("subprocess.run", return_value=fake_proc):
        result = check_clock_skew("192.168.100.14", "nzoyi", "/fake/key", threshold_s=5.0)

    return (
        result["ok"] is True
        and result["error"] is None
        and result["warning"] is not None
        and "Décalage d'horloge" in result["warning"]
        and 2270 < result["skew_s"] < 2290  # ~38min = 2280s, marge pour le temps de test
    )


def test_check_clock_skew_within_threshold_no_warning() -> bool:
    """Décalage négligeable (< seuil) — pas d'avertissement, résultat ok."""
    import time as time_module

    local_now = time_module.time()
    remote_epoch = local_now + 0.2  # 200ms, bien sous le seuil par défaut (5s)

    fake_proc = MagicMock(returncode=0, stdout=f"{remote_epoch:.6f}\n", stderr="")
    with patch("subprocess.run", return_value=fake_proc):
        result = check_clock_skew("192.168.100.14", "nzoyi", "/fake/key", threshold_s=5.0)

    return result["ok"] is True and result["warning"] is None and result["error"] is None


def test_evaluation_agent_unavailable() -> bool:
    ptt = PentestTree("192.168.100.11")
    agent = EvaluationAgent(ptt, load_profile("stealth"), use_llm=False)
    agent.rf_client.predict = lambda features: None
    result = agent.run(dry_run=False, eve_log="/nonexistent/eve.json")
    return (
        result["suricata_detected"] is False
        and result["rf_detected"] is False
        and result["detected"] is False
        and result["source"] == "unavailable"
    )


# ── ids_backend interchangeable (J8) — non-régression + backend zeek_ml ───


def test_evaluation_agent_default_ids_backend_is_suricata() -> bool:
    """Sans ``ids_backend``, le comportement reste EXACTEMENT celui d'avant J8 :
    backend "suricata" et reader SuricataLogReader instancié en interne."""
    now = datetime.now(timezone.utc)
    tmp = _write_eve_fixture("eve_default_backend.json", [_alert_event(now)])
    try:
        ptt = PentestTree("192.168.100.11")
        agent = EvaluationAgent(ptt, load_profile("stealth"), use_llm=False)
        agent.rf_client.predict = lambda features: None
        agent.run(dry_run=False, eve_log=str(tmp))
        reader_type_ok = isinstance(agent._reader, SuricataLogReader)
    finally:
        tmp.unlink(missing_ok=True)
    return agent.ids_backend == "suricata" and reader_type_ok


def test_evaluation_agent_rejects_invalid_ids_backend() -> bool:
    ptt = PentestTree("192.168.100.11")
    try:
        EvaluationAgent(ptt, load_profile("stealth"), use_llm=False, ids_backend="nope")
        return False
    except ValueError:
        return True


def test_evaluation_agent_zeek_ml_backend_fusion() -> bool:
    """Le backend zeek_ml doit fusionner anomalie Zeek+ML et verdict RF, de la
    même façon que le backend suricata (clés de résultat inchangées)."""
    now = datetime.now(timezone.utc)
    tmp = _write_zeek_ml_fixture(
        "zeek_ml_eval_generated.log", [_zeek_ml_line(now, "conn", score=2.0)]
    )
    try:
        ptt = PentestTree("192.168.100.11")
        agent = EvaluationAgent(
            ptt,
            load_profile("stealth"),
            attacker_ip="192.168.100.10",
            use_llm=False,
            ids_backend="zeek_ml",
        )
        agent.rf_client.predict = lambda features: {"label": 1, "proba": 0.9}
        result = agent.run(dry_run=False, eve_log=str(tmp))
    finally:
        tmp.unlink(missing_ok=True)

    return (
        agent.ids_backend == "zeek_ml"
        and result["suricata_detected"] is True  # nom de clé conservé (voir docstring)
        and result["rf_detected"] is True
        and result["detected"] is True
        and result["alert_count"] == 1
        and "ZEEK_ML" in result["signatures"][0]
    )


def test_evaluation_agent_zeek_ml_backend_unavailable() -> bool:
    """Backend zeek_ml, log absent → signal neutre, pas de crash (même contrat
    que le backend suricata)."""
    ptt = PentestTree("192.168.100.11")
    agent = EvaluationAgent(ptt, load_profile("stealth"), use_llm=False, ids_backend="zeek_ml")
    agent.rf_client.predict = lambda features: None
    result = agent.run(dry_run=False, eve_log="/nonexistent/zeek_ml_anomalies.log")
    return (
        result["suricata_detected"] is False
        and result["detected"] is False
        and result["source"] == "unavailable"
    )


def test_orchestrator_default_ids_backend_is_suricata() -> bool:
    """Non-régression : un OrchestratorAgent construit sans ids_backend donne
    un EvaluationAgent en mode suricata, comme avant J8."""
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=False)
    return orchestrator.ids_backend == "suricata" and orchestrator.evaluation.ids_backend == "suricata"


def test_orchestrator_ids_backend_propagates_to_evaluation() -> bool:
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(
        ptt, load_profile("stealth"), use_llm=False, ids_backend="zeek_ml"
    )
    return orchestrator.ids_backend == "zeek_ml" and orchestrator.evaluation.ids_backend == "zeek_ml"


def test_rf_client_normalizes_lab_response() -> bool:
    """L'API lab renvoie prediction/score — le client normalise en label/proba."""
    from nzoyi.tools.rf_client import RFClient

    out = RFClient._normalize({"prediction": 1, "score": 0.72, "model_version": "x"})
    legacy = RFClient._normalize({"label": 0, "proba": 0.1})
    return out == {"label": 1, "proba": 0.72} and legacy == {"label": 0, "proba": 0.1}


def test_rf_features_unsw_payload_complete() -> bool:
    """Le payload RF contient toutes les features UNSW exigées par l'API."""
    from nzoyi.tools.rf_features import UNSW_FEATURE_NAMES, features_from_evasion

    feat = features_from_evasion(
        {"state": (2, 5, 1)},
        nmap_timing="T2",
        scan_delay_ms=500,
        packet_fragment=True,
    )
    return set(feat.keys()) == set(UNSW_FEATURE_NAMES) and feat["rate"] == 40.0


# ── Benchmark IDS multi-modèles (préprocesseur, modèles, métriques, API) ──


def _tiny_unsw_frame(rows: int, seed_offset: int = 0) -> pd.DataFrame:
    """Petit DataFrame synthétique au format UNSW-NB15 (id/attack_cat/label inclus)."""
    return pd.DataFrame(
        {
            "id": range(seed_offset, seed_offset + rows),
            "dur": [0.01 * (i + 1) for i in range(rows)],
            "rate": [float(i % 5) for i in range(rows)],
            "proto": ["tcp" if i % 2 == 0 else "udp" for i in range(rows)],
            "service": ["-" for _ in range(rows)],
            "state": ["FIN" if i % 3 else "INT" for i in range(rows)],
            "attack_cat": ["Normal" if i % 2 == 0 else "Generic" for i in range(rows)],
            "label": [0 if i % 2 == 0 else 1 for i in range(rows)],
        }
    )


def test_benchmark_data_split_removes_leakage_and_coerces() -> bool:
    """split_features_target retire id/attack_cat/label et coerce les numériques."""
    from benchmark.data import split_features_target

    df = _tiny_unsw_frame(6)
    df["dur"] = df["dur"].astype(object)
    df.loc[2, "dur"] = "N/A"  # valeur mal typée, courante dans le CSV officiel

    X, y = split_features_target(df, source="synthétique")

    return (
        "id" not in X.columns
        and "attack_cat" not in X.columns
        and "label" not in X.columns
        and list(y) == [0, 1, 0, 1, 0, 1]
        and X["dur"].isna().sum() == 1
    )


def test_benchmark_data_missing_columns_raise() -> bool:
    """split_features_target lève une erreur claire si 'label' est absent."""
    from benchmark.data import split_features_target

    df = _tiny_unsw_frame(3).drop(columns=["label"])
    try:
        split_features_target(df, source="synthétique")
        return False
    except ValueError:
        return True


def test_benchmark_data_missing_files_raise() -> bool:
    """load_official_split lève FileNotFoundError si les CSV sont absents."""
    from benchmark.data import load_official_split

    with tempfile.TemporaryDirectory() as tmp:
        try:
            load_official_split(tmp)
            return False
        except FileNotFoundError:
            return True


def test_benchmark_preprocessing_shared_pipeline() -> bool:
    """Le préprocesseur, fitté sur le train, transforme le test sans le refitter."""
    from benchmark.data import split_features_target
    from benchmark.preprocessing import fit_preprocessor

    train_df = _tiny_unsw_frame(10, seed_offset=0)
    test_df = _tiny_unsw_frame(4, seed_offset=100)
    test_df.loc[0, "proto"] = "icmp"  # catégorie absente du train

    X_train, _ = split_features_target(train_df, source="train")
    X_test, _ = split_features_target(test_df, source="test")

    preprocessor = fit_preprocessor(X_train)
    X_train_t = preprocessor.transform(X_train)
    X_test_t = preprocessor.transform(X_test)  # ne doit pas lever malgré "icmp" inédit

    return (
        X_train_t.shape[1] == X_test_t.shape[1]
        and X_test_t.shape[0] == 4
    )


def test_benchmark_models_factory_hyperparameters() -> bool:
    """La factory instancie les 5 modèles avec les hyperparamètres imposés."""
    from benchmark.models import MODEL_NAMES, get_models

    models = get_models(scale_pos_weight=4.5)
    if set(models) != set(MODEL_NAMES):
        return False

    rf = models["random_forest"].get_params()
    xgb = models["xgboost"].get_params()
    mlp = models["mlp"].get_params()
    logreg = models["logistic_regression"].get_params()
    knn = models["knn"].get_params()

    return (
        rf["n_estimators"] == 100 and rf["class_weight"] == "balanced" and rf["random_state"] == 42
        and xgb["max_depth"] == 6 and xgb["learning_rate"] == 0.1 and xgb["scale_pos_weight"] == 4.5
        and mlp["hidden_layer_sizes"] == (128, 64) and mlp["early_stopping"] is True
        and logreg["C"] == 1.0 and logreg["class_weight"] == "balanced"
        and knn["n_neighbors"] == 5 and knn["weights"] == "distance"
    )


def test_benchmark_resolve_model_alias() -> bool:
    """resolve_model_name accepte les alias NZOYI_IDS_MODEL et rejette l'inconnu."""
    from benchmark.models import resolve_model_name

    try:
        resolve_model_name("does-not-exist")
        return False
    except ValueError:
        pass

    return (
        resolve_model_name("RF") == "random_forest"
        and resolve_model_name("xgb") == "xgboost"
        and resolve_model_name("logreg") == "logistic_regression"
        and resolve_model_name("kneighbors") == "knn"
    )


def test_benchmark_metrics_confusion_and_rates() -> bool:
    """FPR/FNR et la matrice de confusion sont cohérents (malicious=1=positif)."""
    from benchmark.metrics import evaluate_predictions

    y_true = [0, 0, 1, 1, 1]
    y_pred = [0, 1, 1, 0, 1]
    y_proba = [0.1, 0.6, 0.9, 0.4, 0.8]

    metrics = evaluate_predictions(y_true, y_pred, y_proba)
    cm = metrics["confusion_matrix"]

    return (
        cm == {"tn": 1, "fp": 1, "fn": 1, "tp": 2}
        and abs(metrics["fpr"] - 0.5) < 1e-9
        and abs(metrics["fnr"] - (1 / 3)) < 1e-6
    )


def test_service_api_predict_contract() -> bool:
    """L'API Flask sert prediction/score inchangés et valide colonnes manquantes/inattendues."""
    import joblib
    from sklearn.ensemble import RandomForestClassifier

    from benchmark.data import split_features_target
    from benchmark.preprocessing import fit_preprocessor, save_preprocessor
    from service.app import create_app

    train_df = _tiny_unsw_frame(12)
    X_train, y_train = split_features_target(train_df, source="train")
    preprocessor = fit_preprocessor(X_train)
    X_train_t = preprocessor.transform(X_train)

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train_t, y_train)

    with tempfile.TemporaryDirectory() as tmp:
        models_dir = Path(tmp)
        save_preprocessor(preprocessor, models_dir / "preprocessor.joblib")
        joblib.dump(model, models_dir / "random_forest.joblib")

        app = create_app(models_dir=str(models_dir), model_alias="rf")
        client = app.test_client()

        sample = {col: X_train.iloc[0][col] for col in X_train.columns}

        ok_resp = client.post("/predict", json=sample)
        ok_body = ok_resp.get_json()

        missing_resp = client.post("/predict", json={"dur": 0.1})
        unexpected_resp = client.post("/predict", json={**sample, "bogus_col": 1})
        bad_body_resp = client.post("/predict", json=[1, 2, 3])

        return (
            ok_resp.status_code == 200
            and set(ok_body) == {"prediction", "score", "model"}
            and ok_body["prediction"] in (0, 1)
            and ok_body["model"] == "random_forest"
            and missing_resp.status_code == 400
            and "missing" in missing_resp.get_json()
            and unexpected_resp.status_code == 400
            and "unexpected" in unexpected_resp.get_json()
            and bad_body_resp.status_code == 400
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
    # Fichier vide au départ : baseline_ids() ignore l'historique recon ;
    # l'alerte est écrite pendant l'attaque (comme Suricata en conditions réelles).
    tmp = _write_eve_fixture("eve_pipeline_generated.json", [])
    fake_ports = [
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache", "version": "2.4.49", "protocol": "tcp"},
    ]

    def _scan_and_alert(*_args, **_kwargs):
        with open(tmp, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(_alert_event(now)) + "\n")
        return fake_ports

    try:
        ptt = PentestTree("192.168.100.11")
        orchestrator = OrchestratorAgent(
            ptt, load_profile("stealth"), eve_log=str(tmp), attacker_ip="192.168.100.10", use_llm=False,
        )
        with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", side_effect=_scan_and_alert), \
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


class _FakeLLMBackend(LLMBackend):
    """Backend LLM factice pour les tests — ne fait aucun appel réseau."""

    def __init__(self, text: str | None = None, raises: bool = False) -> None:
        self._text = text
        self._raises = raises

    def decide(self, system_prompt: str, user_message: str) -> str:
        if self._raises:
            raise LLMBackendError("échec simulé du backend")
        return self._text or ""


def test_llm_orchestrator_disabled_skips_backend_construction() -> bool:
    """enabled=False doit retourner le repli exact sans jamais construire AnthropicBackend."""
    with patch("nzoyi.llm.backend_resolver.AnthropicBackend") as mock_backend_cls:
        planner = LLMOrchestrator(enabled=False)
        plan = planner.decide({"target": "192.168.100.14"})
    return (
        mock_backend_cls.call_count == 0
        and planner.backend is None
        and plan["profil"] == "stealth"
        and plan["ports_cibles"] == [22, 80, 21]
        and plan["services_focus"] == []
        and plan["lancer_boucle_evasion"] is True
        and plan["cycles"] == 100
        and plan["raison"] == "fallback hors-ligne"
    )


def test_llm_orchestrator_backend_valid_json_logs_raw_response() -> bool:
    """Un backend simulé renvoyant un JSON valide doit produire le plan attendu
    (via `_sanitize`) et loguer le texte brut dans le PTT (`llm_raw_response`)."""
    raw_text = json.dumps({
        "profil": "aggressive",
        "ports_cibles": [443, 8080],
        "services_focus": ["https"],
        "lancer_boucle_evasion": False,
        "cycles": 77,
        "raison": "cible riche en services web",
    })
    fake_backend = _FakeLLMBackend(text=raw_text)

    ptt = PentestTree("192.168.100.12")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=True)

    # Force explicitement le provider "anthropic" : sans ça, un NZOYI_LLM_PROVIDER
    # ambiant (ex. un .env réel pointant vers Ollama/OpenRouter) ferait résoudre
    # "openai_compatible" et construirait un VRAI OpenAICompatibleBackend (non
    # mocké ici) au lieu de l'AnthropicBackend patché — un appel réseau réel
    # dans la suite de tests, ce qui n'est jamais acceptable.
    with patch.dict(
        "os.environ",
        {"ANTHROPIC_API_KEY": "sk-ant-fake", "NZOYI_LLM_PROVIDER": "anthropic"},
    ), patch("nzoyi.llm.backend_resolver.AnthropicBackend", return_value=fake_backend):
        plan = orchestrator._strategic_plan()

    raw_nodes = ptt.find(kind="llm_raw_response")
    return (
        plan["profil"] == "aggressive"
        and plan["ports_cibles"] == [443, 8080]
        and plan["services_focus"] == ["https"]
        and plan["lancer_boucle_evasion"] is False
        and plan["cycles"] == 77
        and len(raw_nodes) == 1
        and raw_nodes[0].data["raw"] == raw_text
    )


def test_llm_orchestrator_backend_error_triggers_fallback() -> bool:
    """Un backend simulé qui lève LLMBackendError doit retomber sur le repli déterministe."""
    fake_backend = _FakeLLMBackend(raises=True)
    planner = LLMOrchestrator(backend=fake_backend, enabled=True)
    plan = planner.decide({"target": "192.168.100.13"})
    return (
        plan["profil"] == "stealth"
        and plan["raison"] == "fallback hors-ligne"
        and planner.last_raw_response is None
    )


def test_anthropic_backend_scrubs_api_key_from_errors() -> bool:
    """LLMBackendError ne doit JAMAIS exposer la clé API — quel que soit le
    format sous lequel le SDK Anthropic l'aurait incluse dans sa propre
    exception (entière, tronquée, ré-encodée, …). Le message propagé doit être
    un texte générique fixe, et le détail complet de l'exception d'origine doit
    atterrir uniquement dans les logs serveur (`logger.error(..., exc_info=True)`),
    jamais dans l'exception propagée ni, par extension, dans le PTT. Aucun appel
    réseau réel : le client Anthropic est entièrement mocké."""
    fake_key = "sk-ant-TEST-SECRET-KEY-0000"

    class _FakeMessages:
        def create(self, **kwargs):
            raise RuntimeError(f"authentication failed for api_key={fake_key}")

    class _FakeClient:
        messages = _FakeMessages()

    with patch("nzoyi.llm.backends.anthropic_backend.anthropic") as mock_anthropic, \
         patch("nzoyi.llm.backends.anthropic_backend.logger") as mock_logger:
        mock_anthropic.Anthropic.return_value = _FakeClient()
        backend = AnthropicBackend(model="claude-sonnet-5", temperature=0.0, api_key=fake_key)
        try:
            backend.decide("system prompt", "user message")
            return False  # un LLMBackendError était attendu
        except LLMBackendError as exc:
            message = str(exc)
            generic_message_ok = (
                fake_key not in message
                and message == "Échec de l'appel au backend Anthropic"
            )
            # Le détail complet (avec la clé) doit être allé dans les logs
            # serveur — jamais ailleurs — avec exc_info=True pour la stack
            # trace complète côté diagnostic.
            mock_logger.error.assert_called_once()
            _, log_kwargs = mock_logger.error.call_args
            logged_with_exc_info = log_kwargs.get("exc_info") is True
            return generic_message_ok and logged_with_exc_info


# ── Couche stratégique LLM — sélection de provider (J2 : OpenAICompatibleBackend) ──

def test_llm_orchestrator_provider_selection_valid_and_invalid() -> bool:
    """NZOYI_LLM_PROVIDER sélectionne le backend construit ; une valeur
    invalide logue un warning et retombe sur "anthropic" sans jamais lever."""
    with patch("nzoyi.llm.backend_resolver.AnthropicBackend") as mock_anthropic_cls, \
         patch("nzoyi.llm.backend_resolver.OpenAICompatibleBackend") as mock_compat_cls:
        mock_anthropic_cls.return_value = _FakeLLMBackend(text="{}")
        mock_compat_cls.return_value = _FakeLLMBackend(text="{}")

        # 1) Provider absent -> "anthropic" par défaut (non-régression J1).
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-fake"}, clear=False):
            os.environ.pop("NZOYI_LLM_PROVIDER", None)
            planner_default = LLMOrchestrator(enabled=True)
        default_ok = (
            planner_default.provider == "anthropic"
            and mock_anthropic_cls.call_count == 1
            and mock_compat_cls.call_count == 0
        )

        mock_anthropic_cls.reset_mock()
        mock_compat_cls.reset_mock()

        # 2) Provider explicite "openai_compatible" -> OpenAICompatibleBackend,
        #    avec les défauts OpenRouter/DeepSeek-R1 résolus par l'env.
        with patch.dict(
            "os.environ",
            {
                "NZOYI_LLM_PROVIDER": "openai_compatible",
                "NZOYI_OPENAI_COMPAT_API_KEY": "sk-or-fake",
            },
            clear=False,
        ):
            os.environ.pop("NZOYI_OPENAI_COMPAT_BASE_URL", None)
            os.environ.pop("NZOYI_OPENAI_COMPAT_MODEL", None)
            planner_compat = LLMOrchestrator(enabled=True)
        compat_call_kwargs = mock_compat_cls.call_args.kwargs
        compat_ok = (
            planner_compat.provider == "openai_compatible"
            and mock_compat_cls.call_count == 1
            and mock_anthropic_cls.call_count == 0
            and compat_call_kwargs["base_url"] == "https://openrouter.ai/api/v1"
            and compat_call_kwargs["model"] == "deepseek/deepseek-r1"
            and compat_call_kwargs["api_key"] == "sk-or-fake"
        )

        mock_anthropic_cls.reset_mock()
        mock_compat_cls.reset_mock()

        # 3) Provider invalide -> warning + repli sur "anthropic", jamais d'exception.
        with patch.dict(
            "os.environ",
            {"NZOYI_LLM_PROVIDER": "provider-inexistant", "ANTHROPIC_API_KEY": "sk-ant-fake"},
            clear=False,
        ):
            planner_invalid = LLMOrchestrator(enabled=True)
        invalid_ok = (
            planner_invalid.provider == "anthropic"
            and mock_anthropic_cls.call_count == 1
            and mock_compat_cls.call_count == 0
        )

    return default_ok and compat_ok and invalid_ok


def test_llm_orchestrator_openai_compat_without_api_key_stays_none() -> bool:
    """provider=openai_compatible sans NZOYI_OPENAI_COMPAT_API_KEY ne doit
    jamais construire OpenAICompatibleBackend ; comportement identique à J1
    avec ANTHROPIC_API_KEY absente (repli déterministe, self.backend reste None)."""
    with patch("nzoyi.llm.backend_resolver.OpenAICompatibleBackend") as mock_compat_cls, \
         patch.dict("os.environ", {"NZOYI_LLM_PROVIDER": "openai_compatible"}, clear=False):
        os.environ.pop("NZOYI_OPENAI_COMPAT_API_KEY", None)
        planner = LLMOrchestrator(enabled=True)
        plan = planner.decide({"target": "192.168.100.15"})
    return (
        mock_compat_cls.call_count == 0
        and planner.backend is None
        and plan["raison"] == "fallback hors-ligne"
    )


def test_llm_orchestrator_openai_compat_backend_error_triggers_fallback() -> bool:
    """provider=openai_compatible : si le backend construit lève LLMBackendError
    lors de decide(), l'Orchestrator retombe sur le repli déterministe — même
    comportement que pour Anthropic, désormais vérifié à travers la sélection
    de provider elle-même (pas seulement via injection directe de `backend=`)."""
    fake_backend = _FakeLLMBackend(raises=True)
    with patch(
        "nzoyi.llm.backend_resolver.OpenAICompatibleBackend", return_value=fake_backend
    ), patch.dict(
        "os.environ",
        {
            "NZOYI_LLM_PROVIDER": "openai_compatible",
            "NZOYI_OPENAI_COMPAT_API_KEY": "sk-or-fake",
        },
        clear=False,
    ):
        planner = LLMOrchestrator(enabled=True)
        plan = planner.decide({"target": "192.168.100.16"})
    return (
        planner.provider == "openai_compatible"
        and plan["profil"] == "stealth"
        and plan["raison"] == "fallback hors-ligne"
        and planner.last_raw_response is None
    )


def test_openai_compat_backend_generic_error_never_leaks_api_key() -> bool:
    """LLMBackendError (OpenAICompatibleBackend) ne doit JAMAIS exposer la clé
    API, quel que soit le format sous lequel le SDK l'aurait incluse dans sa
    propre exception. Message générique fixe ; le détail complet de
    l'exception d'origine part uniquement dans les logs serveur
    (`logger.error(..., exc_info=True)`), jamais dans l'exception propagée ni,
    par extension, dans le PTT. Aucun appel réseau réel."""
    fake_key = "sk-or-TEST-SECRET-KEY-0000"

    class _FakeCompletions:
        def create(self, **kwargs):
            raise RuntimeError(f"authentication failed for api_key={fake_key}")

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    with patch("nzoyi.llm.backends.openai_compat_backend.openai") as mock_openai, \
         patch("nzoyi.llm.backends.openai_compat_backend.logger") as mock_logger:
        mock_openai.OpenAI.return_value = _FakeClient()
        backend = OpenAICompatibleBackend(
            base_url="https://openrouter.ai/api/v1",
            model="deepseek/deepseek-r1",
            api_key=fake_key,
        )
        try:
            backend.decide("system prompt", "user message")
            return False  # un LLMBackendError était attendu
        except LLMBackendError as exc:
            message = str(exc)
            generic_message_ok = (
                fake_key not in message
                and message == "Échec de l'appel au backend OpenAI-compatible"
            )
            mock_logger.error.assert_called_once()
            _, log_kwargs = mock_logger.error.call_args
            logged_with_exc_info = log_kwargs.get("exc_info") is True
            return generic_message_ok and logged_with_exc_info


def test_openai_compat_backend_omits_none_kwargs() -> bool:
    """decide() n'ajoute `temperature`/`reasoning_effort` aux kwargs de l'appel
    que lorsque la valeur correspondante n'est pas None — jamais les deux
    forcés en même temps (un fournisseur donné ne supporte en général que l'un
    des deux)."""
    captured_kwargs: list[dict] = []

    class _FakeMessage:
        content = '{"profil": "stealth"}'

    class _FakeChoice:
        message = _FakeMessage()

    class _FakeResponse:
        choices = [_FakeChoice()]

    class _FakeCompletions:
        def create(self, **kwargs):
            captured_kwargs.append(kwargs)
            return _FakeResponse()

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    with patch("nzoyi.llm.backends.openai_compat_backend.openai") as mock_openai:
        mock_openai.OpenAI.return_value = _FakeClient()

        # Cas 1 : temperature=0.0 fourni, reasoning_effort=None (OpenRouter/
        # DeepSeek-R1) -> seul `temperature` doit apparaître dans les kwargs.
        backend_temp = OpenAICompatibleBackend(
            base_url="https://openrouter.ai/api/v1",
            model="deepseek/deepseek-r1",
            api_key="sk-or-fake",
            temperature=0.0,
            reasoning_effort=None,
        )
        backend_temp.decide("sys", "user")

        # Cas 2 : reasoning_effort="low" fourni, temperature=None (GPT-6 Astra,
        # pressenti) -> seul `reasoning_effort` doit apparaître dans les kwargs.
        backend_effort = OpenAICompatibleBackend(
            base_url="https://openrouter.ai/api/v1",
            model="gpt-6-astra",
            api_key="sk-fake",
            temperature=None,
            reasoning_effort="low",
        )
        backend_effort.decide("sys", "user")

    temp_call, effort_call = captured_kwargs
    return (
        "temperature" in temp_call
        and temp_call["temperature"] == 0.0
        and "reasoning_effort" not in temp_call
        and "reasoning_effort" in effort_call
        and effort_call["reasoning_effort"] == "low"
        and "temperature" not in effort_call
    )


# ── Panel LLM J5/J6 — VulnTriage / AttackPriority / EvaluationRationale ────

def test_vuln_triage_disabled_falls_back_by_severity() -> bool:
    """enabled=False doit trier par sévérité (critical > high > medium),
    puis par ordre d'apparition — sans jamais appeler de backend."""
    findings = [
        {"cve_id": "CVE-A", "severity": "high", "port": 80},
        {"cve_id": "CVE-B", "severity": "critical", "port": 22},
        {"cve_id": "CVE-C", "severity": "medium", "port": 8080},
    ]
    triage = VulnTriageLLM(enabled=False)
    ordered = triage.decide(findings)
    return (
        [f["cve_id"] for f in ordered] == ["CVE-B", "CVE-A", "CVE-C"]
        and triage.last_raw_response is None
    )


def test_vuln_triage_backend_valid_response_reorders() -> bool:
    """Un backend simulé renvoyant un ordre valide (incomplet) doit réordonner
    les findings et rajouter le CVE omis à la fin — jamais une vulnérabilité
    perdue."""
    findings = [
        {"cve_id": "CVE-A", "severity": "high", "port": 80},
        {"cve_id": "CVE-B", "severity": "critical", "port": 22},
        {"cve_id": "CVE-C", "severity": "medium", "port": 8080},
    ]
    raw_text = json.dumps({"ordre_cve_ids": ["CVE-C", "CVE-A"], "raison": "web d'abord"})
    fake_backend = _FakeLLMBackend(text=raw_text)
    triage = VulnTriageLLM(backend=fake_backend, enabled=True)
    ordered = triage.decide(findings)
    return (
        [f["cve_id"] for f in ordered] == ["CVE-C", "CVE-A", "CVE-B"]
        and triage.last_raw_response == raw_text
    )


def test_vuln_triage_backend_error_triggers_fallback() -> bool:
    """Un backend simulé qui lève LLMBackendError doit retomber sur le tri
    déterministe par sévérité."""
    findings = [
        {"cve_id": "CVE-A", "severity": "medium", "port": 80},
        {"cve_id": "CVE-B", "severity": "critical", "port": 22},
    ]
    triage = VulnTriageLLM(backend=_FakeLLMBackend(raises=True), enabled=True)
    ordered = triage.decide(findings)
    return (
        [f["cve_id"] for f in ordered] == ["CVE-B", "CVE-A"]
        and triage.last_raw_response is None
    )


def test_vuln_triage_sanitize_filters_unknown_ids() -> bool:
    """_sanitize doit ignorer tout id hors de l'ensemble des findings réels,
    et rajouter à la fin tout cve_id connu omis par le modèle."""
    findings = [
        {"cve_id": "CVE-A", "severity": "high", "port": 80},
        {"cve_id": "CVE-B", "severity": "critical", "port": 22},
        {"cve_id": "CVE-C", "severity": "medium", "port": 8080},
    ]
    ordered = VulnTriageLLM._sanitize(
        {"ordre_cve_ids": ["CVE-INVENTE", "CVE-B"], "raison": "x"}, findings
    )
    return [f["cve_id"] for f in ordered] == ["CVE-B", "CVE-A", "CVE-C"]


def test_attack_priority_disabled_keeps_target_ports() -> bool:
    """enabled=False doit conserver target_ports sans aucune modification."""
    priority = AttackPriorityLLM(enabled=False)
    plan = priority.decide([22, 80], [{"port": 9999, "cve_id": "CVE-X", "severity": "critical"}])
    return (
        plan["ports_prioritaires"] == [22, 80]
        and plan["raison"] == "fallback hors-ligne"
        and priority.last_raw_response is None
    )


def test_attack_priority_backend_valid_response_allows_critical_port() -> bool:
    """Un port hors target_ports mais porteur d'un CVE critical doit être
    autorisé ; l'ordre proposé par le modèle doit être respecté."""
    target_ports = [22, 80]
    findings = [{"port": 9999, "cve_id": "CVE-CRIT", "severity": "critical"}]
    raw_text = json.dumps({"ports_prioritaires": [80, 22, 9999], "raison": "web + CVE critique"})
    priority = AttackPriorityLLM(backend=_FakeLLMBackend(text=raw_text), enabled=True)
    plan = priority.decide(target_ports, findings)
    return (
        plan["ports_prioritaires"] == [80, 22, 9999]
        and priority.last_raw_response == raw_text
    )


def test_attack_priority_backend_error_triggers_fallback() -> bool:
    """Un backend simulé qui lève LLMBackendError doit conserver target_ports
    sans aucune modification."""
    priority = AttackPriorityLLM(backend=_FakeLLMBackend(raises=True), enabled=True)
    plan = priority.decide([22, 80], [])
    return plan["ports_prioritaires"] == [22, 80] and plan["raison"] == "fallback hors-ligne"


def test_attack_priority_sanitize_filters_ports_outside_scope() -> bool:
    """_sanitize doit filtrer tout port qui n'est ni dans target_ports ni
    porteur d'un CVE critical — jamais une cible inventée hors de ce que le
    pipeline a réellement découvert."""
    target_ports = [22, 80]
    findings = [{"port": 9999, "cve_id": "CVE-CRIT", "severity": "critical"}]
    plan = AttackPriorityLLM._sanitize(
        {"ports_prioritaires": [22, 31337, 9999], "raison": "x"}, target_ports, findings
    )
    return plan["ports_prioritaires"] == [22, 9999]


def test_evaluation_rationale_disabled_returns_empty_string() -> bool:
    """enabled=False doit renvoyer une chaîne vide, sans toucher au résultat."""
    rationale = EvaluationRationaleLLM(enabled=False)
    result = {"detected": True, "detection_rate": 0.5}
    text = rationale.decide(result)
    return text == "" and rationale.last_raw_response is None and result["detected"] is True


def test_evaluation_rationale_backend_valid_response() -> bool:
    """Un backend simulé renvoyant un JSON valide doit produire le rationale attendu."""
    raw_text = json.dumps({"rationale": "Détection confirmée par Suricata et le RF."})
    rationale = EvaluationRationaleLLM(backend=_FakeLLMBackend(text=raw_text), enabled=True)
    text = rationale.decide({"detected": True, "detection_rate": 1.0})
    return text == "Détection confirmée par Suricata et le RF." and rationale.last_raw_response == raw_text


def test_evaluation_rationale_backend_error_returns_empty_string() -> bool:
    """Un backend simulé qui lève LLMBackendError doit renvoyer une chaîne vide."""
    rationale = EvaluationRationaleLLM(backend=_FakeLLMBackend(raises=True), enabled=True)
    text = rationale.decide({"detected": False})
    return text == ""


def test_evaluation_rationale_sanitize_truncates_length() -> bool:
    """_sanitize doit tronquer rationale à MAX_RATIONALE_LENGTH caractères."""
    from nzoyi.llm.evaluation_rationale_llm import MAX_RATIONALE_LENGTH
    long_text = "x" * (MAX_RATIONALE_LENGTH + 100)
    truncated = EvaluationRationaleLLM._sanitize({"rationale": long_text})
    return len(truncated) == MAX_RATIONALE_LENGTH


def test_vulnerability_agent_triage_logs_raw_response_in_ptt() -> bool:
    """Intégration : VulnerabilityAgent.run() doit loguer llm_raw_response_vuln
    dans le PTT quand le triage LLM produit une réponse réelle (backend mocké
    au niveau du resolver partagé, aucun appel réseau)."""
    raw_text = json.dumps({"ordre_cve_ids": ["CVE-2017-3167"], "raison": "auth bypass critique"})
    fake_backend = _FakeLLMBackend(text=raw_text)

    ptt = PentestTree("192.168.100.11")
    ptt.set_recon_results([
        {"host": "192.168.100.11", "port": 80, "state": "open", "service": "http",
         "product": "Apache httpd", "version": "2.4.25"},
    ])
    agent = VulnerabilityAgent(ptt, load_profile("stealth"), use_llm=True)

    with patch.dict(
        "os.environ", {"ANTHROPIC_API_KEY": "sk-ant-fake", "NZOYI_LLM_PROVIDER": "anthropic"}
    ), patch("nzoyi.llm.backend_resolver.AnthropicBackend", return_value=fake_backend), \
       patch("nzoyi.agents.vulnerability.detect_dvwa", return_value=None):
        result = agent.run(dry_run=True)

    raw_nodes = ptt.find(kind="llm_raw_response_vuln")
    return (
        len(result["findings"]) >= 1
        and len(raw_nodes) == 1
        and raw_nodes[0].data["raw"] == raw_text
    )


def test_attack_agent_priority_logs_raw_response_in_ptt() -> bool:
    """Intégration : AttackAgent.run() doit loguer llm_raw_response_attack dans
    le PTT quand le raffinement LLM produit une réponse réelle, et appliquer
    l'ordre résultant à target_ports."""
    raw_text = json.dumps({"ports_prioritaires": [80, 22], "raison": "web d'abord"})
    fake_backend = _FakeLLMBackend(text=raw_text)

    ptt = PentestTree("192.168.100.11")
    agent = AttackAgent(ptt, load_profile("stealth"), use_llm=True)
    agent.target_ports = [22, 80]

    with patch.dict(
        "os.environ", {"ANTHROPIC_API_KEY": "sk-ant-fake", "NZOYI_LLM_PROVIDER": "anthropic"}
    ), patch("nzoyi.llm.backend_resolver.AnthropicBackend", return_value=fake_backend), \
       patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=[]):
        agent.run(dry_run=True)

    raw_nodes = ptt.find(kind="llm_raw_response_attack")
    return (
        agent.target_ports == [80, 22]
        and len(raw_nodes) == 1
        and raw_nodes[0].data["raw"] == raw_text
    )


def test_evaluation_agent_rationale_logs_raw_response_in_ptt() -> bool:
    """Intégration : EvaluationAgent.run() doit ajouter result['llm_rationale']
    et loguer llm_raw_response_evaluation dans le PTT, sans jamais toucher à
    detected/detection_rate (calculés avant, inchangés après)."""
    raw_text = json.dumps({"rationale": "Alerte Suricata confirmée, RF neutre."})
    fake_backend = _FakeLLMBackend(text=raw_text)

    ptt = PentestTree("192.168.100.11")
    agent = EvaluationAgent(ptt, load_profile("stealth"), use_rf_online=False, use_llm=True)

    with patch.dict(
        "os.environ", {"ANTHROPIC_API_KEY": "sk-ant-fake", "NZOYI_LLM_PROVIDER": "anthropic"}
    ), patch("nzoyi.llm.backend_resolver.AnthropicBackend", return_value=fake_backend):
        result = agent.run(dry_run=True, eve_log="/nonexistent/eve.json")

    raw_nodes = ptt.find(kind="llm_raw_response_evaluation")
    return (
        result["detected"] is False  # calcul déterministe inchangé (pas de signal)
        and result["llm_rationale"] == "Alerte Suricata confirmée, RF neutre."
        and len(raw_nodes) == 1
        and raw_nodes[0].data["raw"] == raw_text
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


def test_learning_loop_aborted_when_recon_empty() -> bool:
    """Le recon initial ne trouve aucun port -> la campagne est annulée avant tout cycle."""
    ptt = PentestTree("192.168.100.11")
    orchestrator = OrchestratorAgent(ptt, load_profile("stealth"), use_llm=False)

    with patch("nzoyi.tools.nmap_wrapper.NmapWrapper.scan", return_value=[]) as mock_scan:
        result = orchestrator.learning_loop(cycles=5, dry_run=True)

    return (
        result["cycles"] == 0
        and result["convergence"] == []
        and mock_scan.call_count == 1  # seul recon a scanné — jamais evasion/attack
        and len(ptt.find(kind="campaign_aborted")) == 1
    )


def run_all_tests() -> dict[str, bool]:
    return {
        "PTT shared memory": test_ptt_shared_memory(),
        "Q-Learning update cycle": test_qlearning_update(),
        "Stealth profile configuration": test_stealth_profile(),
        "Nmap XML parser": test_nmap_wrapper_cli_parse(),
        "Suricata log reader": test_suricata_log_reader(),
        "Suricata baseline curseur": test_suricata_cursor_baseline_ignores_history(),
        "Suricata timestamp +0000": test_suricata_parses_plus0000_timestamp(),
        "Suricata ignore bruit décodeur": test_suricata_ignores_decoder_noise(),
        "Q-Learning epsilon decay": test_qlearning_convergence(),
        "Q-Learning — as_key() inclut target_signature (J7)": test_evasion_state_as_key_includes_target_signature(),
        "JSON LLM — strip fences ```json...``` (J7-ter)": test_strip_markdown_fences_json_language_tag(),
        "JSON LLM — strip fences nues ```...```": test_strip_markdown_fences_bare(),
        "JSON LLM — sans fences, inchangé": test_strip_markdown_fences_absent_unchanged(),
        "JSON LLM — espaces/retours à la ligne superflus": test_strip_markdown_fences_surrounding_whitespace(),
        "IDS reconciliation — réattribution par horodatage (J7-ter)": test_ids_reconciliation_reattributes_late_arriving_alert(),
        "IDS reconciliation — cycle 1 non contaminé par un backend antérieur": test_ids_reconciliation_cycle1_not_contaminated_by_earlier_backend(),
        "Q-Learning save/load": test_qlearning_save_load(),
        "PTT thread safety": test_ptt_thread_safety(),
        "Recon agent — scan réel (mocké)": test_recon_agent_real_scan(),
        "Recon agent — nmap indisponible": test_recon_agent_nmap_unavailable(),
        "Recon agent — timing découplé du profil": test_recon_agent_timing_decoupled_from_profile(),
        "Enumerator — banner grab": test_enumerator_agent_banner_grab(),
        "Enumerator — service inconnu": test_enumerator_agent_unknown_service(),
        "Vulnerability — corrélation CVE": test_vulnerability_agent_correlation(),
        "Vulnerability — Apache lab 2.4.25": test_vulnerability_agent_apache_lab_version(),
        "Vulnerability — détection DVWA + SQLi/XSS": test_vulnerability_agent_dvwa_detection(),
        "Vulnerability — aucune correspondance": test_vulnerability_agent_no_match(),
        "Vulnerability — repli sur énumération": test_vulnerability_agent_fallback_to_enumeration(),
        "Evasion — oracle RF indisponible": test_evasion_agent_oracle_unavailable(),
        "Evasion — oracle RF mocké": test_evasion_agent_with_mocked_oracle(),
        "Attack — mode plan (dry-run)": test_attack_agent_dry_run_plan(),
        "Attack — exécution réelle (mockée)": test_attack_agent_real_execution(),
        "Attack — aucun port, aucune exécution": test_attack_agent_no_ports_no_execution(),
        "Attack — scan restreint aux ports découverts": test_attack_agent_restricts_to_discovered_ports(),
        "Attack — timeout non bloquant (non abouti)": test_attack_agent_timeout_not_fatal(),
        "Attack — applique stratégie Q-Learning": test_attack_applies_evasion_strategy(),
        "Evaluation — fusion Suricata + RF": test_evaluation_agent_fusion(),
        "Campagne J7 — garde-fou décalage d'horloge détecté (J7-ter)": test_check_clock_skew_detects_significant_drift(),
        "Campagne J7 — décalage d'horloge sous le seuil, pas d'alerte": test_check_clock_skew_within_threshold_no_warning(),
        "Evaluation — signaux indisponibles": test_evaluation_agent_unavailable(),
        "RF client — normalisation prediction/score": test_rf_client_normalizes_lab_response(),
        "RF features — payload UNSW complet": test_rf_features_unsw_payload_complete(),
        "Benchmark — split retire id/attack_cat, coerce numériques": test_benchmark_data_split_removes_leakage_and_coerces(),
        "Benchmark — colonnes manquantes détectées": test_benchmark_data_missing_columns_raise(),
        "Benchmark — CSV manquants détectés": test_benchmark_data_missing_files_raise(),
        "Benchmark — préprocesseur unique fit(train)/transform(test)": test_benchmark_preprocessing_shared_pipeline(),
        "Benchmark — hyperparamètres des 5 modèles": test_benchmark_models_factory_hyperparameters(),
        "Benchmark — alias NZOYI_IDS_MODEL": test_benchmark_resolve_model_alias(),
        "Benchmark — FPR/FNR et matrice de confusion": test_benchmark_metrics_confusion_and_rates(),
        "Service Flask — contrat /predict prediction/score": test_service_api_predict_contract(),
        "Orchestrator 7-agent pipeline": test_orchestrator_pipeline(),
        "Pipeline complet — mode plan dry-run": test_full_pipeline_dry_run_plan_mode(),
        "Pipeline complet — signaux online distincts": test_full_pipeline_online_signals(),
        "LLM stratégique — sanitize clamp/validation": test_llm_orchestrator_sanitize_clamps_and_validates(),
        "LLM stratégique — schéma du repli hors-ligne": test_llm_orchestrator_fallback_schema(),
        "LLM backend — enabled=False ne construit pas AnthropicBackend": test_llm_orchestrator_disabled_skips_backend_construction(),
        "LLM backend — JSON valide → sanitize + log PTT llm_raw_response": test_llm_orchestrator_backend_valid_json_logs_raw_response(),
        "LLM backend — LLMBackendError → repli déterministe": test_llm_orchestrator_backend_error_triggers_fallback(),
        "LLM backend Anthropic — clé API expurgée des erreurs": test_anthropic_backend_scrubs_api_key_from_errors(),
        "LLM provider — sélection valide/invalide (J2)": test_llm_orchestrator_provider_selection_valid_and_invalid(),
        "LLM provider — openai_compatible sans clé API": test_llm_orchestrator_openai_compat_without_api_key_stays_none(),
        "LLM provider — openai_compatible, LLMBackendError → repli": test_llm_orchestrator_openai_compat_backend_error_triggers_fallback(),
        "LLM backend OpenAI-compatible — clé API jamais exposée": test_openai_compat_backend_generic_error_never_leaks_api_key(),
        "LLM backend OpenAI-compatible — temperature/reasoning_effort exclusifs": test_openai_compat_backend_omits_none_kwargs(),
        "Panel LLM — VulnTriage désactivé : tri par sévérité": test_vuln_triage_disabled_falls_back_by_severity(),
        "Panel LLM — VulnTriage backend valide : réordonne sans perte": test_vuln_triage_backend_valid_response_reorders(),
        "Panel LLM — VulnTriage LLMBackendError → repli sévérité": test_vuln_triage_backend_error_triggers_fallback(),
        "Panel LLM — VulnTriage sanitize : ids inconnus filtrés": test_vuln_triage_sanitize_filters_unknown_ids(),
        "Panel LLM — AttackPriority désactivé : target_ports conservé": test_attack_priority_disabled_keeps_target_ports(),
        "Panel LLM — AttackPriority backend valide : port critical autorisé": test_attack_priority_backend_valid_response_allows_critical_port(),
        "Panel LLM — AttackPriority LLMBackendError → target_ports conservé": test_attack_priority_backend_error_triggers_fallback(),
        "Panel LLM — AttackPriority sanitize : ports hors périmètre filtrés": test_attack_priority_sanitize_filters_ports_outside_scope(),
        "Panel LLM — EvaluationRationale désactivé : chaîne vide": test_evaluation_rationale_disabled_returns_empty_string(),
        "Panel LLM — EvaluationRationale backend valide": test_evaluation_rationale_backend_valid_response(),
        "Panel LLM — EvaluationRationale LLMBackendError → chaîne vide": test_evaluation_rationale_backend_error_returns_empty_string(),
        "Panel LLM — EvaluationRationale sanitize : troncature": test_evaluation_rationale_sanitize_truncates_length(),
        "Panel LLM — VulnerabilityAgent logue llm_raw_response_vuln": test_vulnerability_agent_triage_logs_raw_response_in_ptt(),
        "Panel LLM — AttackAgent logue llm_raw_response_attack": test_attack_agent_priority_logs_raw_response_in_ptt(),
        "Panel LLM — EvaluationAgent logue llm_raw_response_evaluation": test_evaluation_agent_rationale_logs_raw_response_in_ptt(),
        "Boucle d'évasion avortée par le LLM": test_learning_loop_aborted_by_llm(),
        "Boucle d'apprentissage avortée — recon vide": test_learning_loop_aborted_when_recon_empty(),
        "Zeek+ML (J8) — seuil d'anomalie filtre correctement": test_zeek_ml_log_reader_threshold(),
        "Zeek+ML (J8) — curseur baseline ignore l'historique": test_zeek_ml_cursor_baseline_ignores_history(),
        "Zeek+ML (J8) — fichier log absent lève FileNotFoundError": test_zeek_ml_reader_missing_file_raises(),
        "ids_backend (J8) — défaut suricata inchangé": test_evaluation_agent_default_ids_backend_is_suricata(),
        "ids_backend (J8) — valeur invalide rejetée": test_evaluation_agent_rejects_invalid_ids_backend(),
        "ids_backend (J8) — backend zeek_ml fusionne detected": test_evaluation_agent_zeek_ml_backend_fusion(),
        "ids_backend (J8) — backend zeek_ml, log absent → neutre": test_evaluation_agent_zeek_ml_backend_unavailable(),
        "ids_backend (J8) — orchestrateur défaut = suricata": test_orchestrator_default_ids_backend_is_suricata(),
        "ids_backend (J8) — orchestrateur propage zeek_ml": test_orchestrator_ids_backend_propagates_to_evaluation(),
    }
