"""اختبارات وحدة لتدقيق الجدار الناري (دوال نقيّة بلا I/O) - الفصل 3."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.app.discovery.firewall_audit import classify_rule, evaluate_firewall


def _alert(report, prefix):
    return next((a for a in report.alerts if a.id.startswith(prefix)), None)


def test_classify_packet_filter_rule():
    c = classify_rule({"name": "DB", "direction": "Inbound", "local_port": "1433",
                       "remote_address": "192.168.1.0/24", "protocol": "TCP", "program": None})
    assert "فحص الحالة" in c.classes       # ويندوز stateful دائمًا
    assert "تصفية الحزم" in c.classes       # يُصفّي حسب منفذ/عنوان
    assert "مستوى التطبيق" not in c.classes  # غير مقيَّد ببرنامج


def test_classify_application_level_rule():
    c = classify_rule({"name": "App", "direction": "Inbound", "local_port": "Any",
                       "remote_address": "Any", "protocol": "Any",
                       "program": r"C:\Program Files\App\app.exe"})
    assert "مستوى التطبيق" in c.classes     # مقيَّد ببرنامج
    assert "تصفية الحزم" not in c.classes   # لا تقييد منفذ/عنوان/بروتوكول
    assert "فحص الحالة" in c.classes


def test_disabled_profile_is_critical_alert():
    data = {"profiles": [{"name": "Public", "enabled": False, "inbound": "Block", "outbound": "Allow"}],
            "rules": []}
    report = evaluate_firewall(data)
    a = _alert(report, "fw_profile_off_Public")
    assert a is not None and a.severity == "critical"
    assert "Set-NetFirewallProfile" in a.fix_command


def test_any_any_inbound_rule_flagged():
    data = {"profiles": [], "rules": [
        {"name": "WideOpen", "direction": "Inbound", "profile": "Any",
         "local_port": "Any", "remote_address": "Any", "protocol": "Any", "program": "Any"}
    ]}
    report = evaluate_firewall(data)
    a = _alert(report, "fw_any_any_")
    assert a is not None and a.severity == "high"


def test_high_risk_port_on_public_is_critical():
    data = {"profiles": [], "rules": [
        {"name": "RDP-Public", "direction": "Inbound", "profile": "Public",
         "local_port": "3389", "remote_address": "Any", "protocol": "TCP", "program": None}
    ]}
    report = evaluate_firewall(data)
    a = _alert(report, "fw_public_highrisk_")
    assert a is not None and a.severity == "critical"
    assert "3389" in a.evidence


def test_rule_for_unsigned_program_flagged():
    prog = r"C:\Users\x\AppData\Local\Updates\svc.exe"
    data = {"profiles": [], "rules": [
        {"name": "SneakyApp", "direction": "Inbound", "profile": "Private",
         "local_port": "Any", "remote_address": "Any", "protocol": "Any", "program": prog}
    ]}
    report = evaluate_firewall(data, unsigned_paths={prog})
    a = _alert(report, "fw_unsigned_prog_")
    assert a is not None and a.severity == "high"


def test_rule_for_user_path_program_flagged_medium():
    prog = r"C:\Users\x\AppData\Roaming\tool.exe"
    data = {"profiles": [], "rules": [
        {"name": "UserApp", "direction": "Inbound", "profile": "Private",
         "local_port": "8080", "remote_address": "Any", "protocol": "TCP", "program": prog}
    ]}
    report = evaluate_firewall(data)  # ليس في unsigned_paths لكنه من مسار مستخدم
    a = _alert(report, "fw_unsigned_prog_")
    assert a is not None and a.severity == "medium"


def test_boundaries_and_notes_present():
    report = evaluate_firewall({"profiles": [], "rules": []})
    # الحدود الأربعة من المنهج
    assert len(report.boundaries) == 4
    covered = " ".join(b.covered_by for b in report.boundaries)
    assert "host_activity" in covered
    assert "wifi" in covered and "bluetooth" in covered
    assert "unsigned_programs" in covered
    # مستوى الدائرة والنموذج المرجعي مذكوران كغير منطبقين
    notes = " ".join(report.general_notes)
    assert "الدائرة" in notes and "المرجعي" in notes


def test_clean_firewall_has_no_alerts():
    data = {"profiles": [{"name": "Private", "enabled": True, "inbound": "Block", "outbound": "Allow"}],
            "rules": [{"name": "LocalWeb", "direction": "Inbound", "profile": "Private",
                       "local_port": "8080", "remote_address": "192.168.1.0/24", "protocol": "TCP", "program": None}]}
    report = evaluate_firewall(data)
    assert report.alerts == []
