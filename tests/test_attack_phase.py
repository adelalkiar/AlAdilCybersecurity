"""اختبارات وحدة لوسم مرحلة الهجوم (الفصل 2) - دالة نقيّة."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.models import (
    DeviceFingerprint,
    IntruderStatus,
    OpenPort,
    ScannedDevice,
    Vulnerability,
)
from shared.vuln_db.attack_phase import classify_attack_phase


def _dev(**kw):
    return ScannedDevice(fingerprint=DeviceFingerprint(hostname=kw.pop("hostname", "dev")), **kw)


def test_mere_presence_is_target_selection():
    d = classify_attack_phase(_dev())
    assert d.attack_phase == "target_selection"
    assert len(d.attacker_timeline) == 1
    assert d.attacker_timeline[0]["phase"] == "target_selection"


def test_open_ports_reach_reconnaissance():
    d = classify_attack_phase(_dev(open_ports=[OpenPort(port=22), OpenPort(port=80)]))
    assert d.attack_phase == "reconnaissance"
    phases = [e["phase"] for e in d.attacker_timeline]
    assert "reconnaissance" in phases


def test_accessed_host_is_reconnaissance():
    d = classify_attack_phase(_dev(accessed_host_system=True))
    assert d.attack_phase == "reconnaissance"


def test_failed_attempts_reach_attack():
    d = classify_attack_phase(_dev(failed_connection_attempts=4))
    assert d.attack_phase == "attack"
    assert any("فاشلة" in e["evidence"] for e in d.attacker_timeline)


def test_active_threat_reaches_attack():
    d = _dev()
    d.intruder_status = IntruderStatus.ACTIVE_THREAT
    classify_attack_phase(d)
    assert d.attack_phase == "attack"


def test_full_kill_chain_timeline():
    d = _dev(open_ports=[OpenPort(port=445)], failed_connection_attempts=2,
             vulnerabilities=[Vulnerability(title="SMB")])
    classify_attack_phase(d)
    phases = [e["phase"] for e in d.attacker_timeline]
    assert phases == ["target_selection", "reconnaissance", "attack"]
    assert d.attack_phase == "attack"


def test_timeline_evidence_mentions_vuln_count():
    d = _dev(vulnerabilities=[Vulnerability(title="a"), Vulnerability(title="b")])
    classify_attack_phase(d)
    attack = [e for e in d.attacker_timeline if e["phase"] == "attack"][0]
    assert "2 ثغرة" in attack["evidence"]
