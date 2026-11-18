"""اختبارات وحدة لدالة evaluate_audit النقيّة (بلا I/O): تحويل ناتج
التدقيق للقراءة فقط إلى نقاط ضعف، مع التحقق من الأوامر وحالات الأمان."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.app.discovery.vuln_audit import evaluate_audit


def _finding(findings, fid):
    return next((f for f in findings if f.id == fid), None)


def test_clean_config_produces_no_findings():
    audit = {
        "defender": {"tamper": True, "cloud": 2, "pua": 1, "network_protection": 1, "full_scan_age": 1,
                     "excl_path": [], "excl_process": []},
        "firewall": [{"name": "Public", "enabled": "True", "inbound": "Block", "outbound": "Allow"}],
        "listening": [], "uac": {"lua": 1, "admin_prompt": 5, "secure_desktop": 1},
        "accounts": [{"name": "Guest", "enabled": False}],
        "driver_blocklist": 1, "lsa_ppl": 2, "smartscreen": "Warn", "remote_assistance": 0,
        "llmnr": 0, "autorun": 255, "secure_boot": True, "hvci_enabled": 1, "smb1": False,
        "wifi_open": [], "services_userpath": [], "remote_tools": [],
    }
    assert evaluate_audit(audit) == []


def test_suspicious_defender_exclusion_is_critical():
    audit = {"defender": {"tamper": True, "cloud": 2, "pua": 1, "network_protection": 1,
                          "excl_path": [r"C:\Users\x\AppData\Local\Updates"], "excl_process": ["cmd.exe"]}}
    f = _finding(evaluate_audit(audit), "def_exclusions")
    assert f is not None
    assert f.severity == "critical"
    assert "Remove-MpPreference" in f.fix_command
    assert "Add-MpPreference" in f.undo_command  # التراجع يعيد الاستثناء


def test_firewall_off_is_critical_and_lists_open_db_ports():
    audit = {
        "firewall": [{"name": "Private", "enabled": "False", "inbound": "Block", "outbound": "Allow"}],
        "listening": [{"name": "sqlservr", "addr": "0.0.0.0", "port": 1433}],
    }
    f = _finding(evaluate_audit(audit), "firewall")
    assert f is not None
    assert f.severity == "critical"
    assert "1433" in f.evidence
    assert "Set-NetFirewallProfile" in f.fix_command


def test_uac_no_prompt_is_flagged():
    audit = {"uac": {"lua": 1, "admin_prompt": 0, "secure_desktop": 1}}
    f = _finding(evaluate_audit(audit), "uac")
    assert f is not None
    assert f.severity == "critical"
    assert f.needs_reboot is True


def test_guest_account_enabled_is_flagged():
    audit = {"accounts": [{"name": "Guest", "enabled": True, "password_required": False}]}
    f = _finding(evaluate_audit(audit), "guest")
    assert f is not None
    assert "Disable-LocalUser" in f.fix_command


def test_tamper_protection_is_manual_only():
    audit = {"defender": {"tamper": False, "cloud": 2, "pua": 1, "network_protection": 1}}
    f = _finding(evaluate_audit(audit), "def_tamper")
    assert f is not None
    assert f.is_auto_safe is False  # لا أمر آلي - يدوي عبر واجهة Windows فقط
    assert f.fix_command is None
    assert f.manual_steps


def test_secure_boot_off_is_manual_bios():
    audit = {"secure_boot": False}
    f = _finding(evaluate_audit(audit), "secure_boot")
    assert f is not None
    assert f.is_auto_safe is False
    assert any("BIOS" in s for s in f.manual_steps)


def test_smb1_enabled_is_high():
    audit = {"smb1": True}
    f = _finding(evaluate_audit(audit), "smb1")
    assert f is not None
    assert f.severity == "high"


def test_open_wifi_produces_per_network_finding():
    audit = {"wifi_open": ["Earthlink WiFi"]}
    findings = evaluate_audit(audit)
    f = _finding(findings, "wifi_Earthlink WiFi")
    assert f is not None
    assert "connectionmode=manual" in f.fix_command


def test_findings_are_detection_only_never_mutate_input():
    audit = {"uac": {"lua": 0, "admin_prompt": 0, "secure_desktop": 0}}
    before = dict(audit)
    evaluate_audit(audit)
    assert audit == before  # الدالة نقيّة: لا تغيّر مدخلاتها إطلاقًا
