"""Helpers may enrich evidence, not authorize download mode or presence."""
from __future__ import annotations

import json
import re

from ttg_device_xray.models import CommandEvidence
from ttg_device_xray.transports.spd_diagnostic import SpdDiagnosticProbe


class FilteredRunner:
    def __init__(self, pnp, helper):
        self.pnp = pnp
        self.helper = helper

    def exists(self, exe):
        return exe == "powershell"

    def run(self, command, timeout=20):
        if command[0] == "powershell":
            expression = command[-1]
            match = re.search(r"\$pattern = '([^']+)'", expression)
            assert match, "expected real source PowerShell inventory filter"
            item = self.pnp
            name = item["PNPDeviceID"] + " " + item["Name"]
            passed = bool(re.search(match.group(1), name, flags=re.IGNORECASE))
            output = json.dumps(item) if passed else ""
        else:
            output = json.dumps(self.helper)
        return CommandEvidence(command=command, return_code=0, stdout=output)


def device(name="SPRD U2S Diag (COM52)", pid="4D00"):
    return {
        "Name": name,
        "PNPDeviceID": rf"USB\VID_1782&PID_{pid}\LIVE",
        "Present": True,
        "Status": "OK",
    }


def test_real_windows_discovery_regex_accepts_only_matching_diagnostic():
    good = SpdDiagnosticProbe(FilteredRunner(device(), {})).probe()
    assert len(good) == 1 and good[0].connected
    assert good[0].mode == "diagnostic"

    wrong_pid = SpdDiagnosticProbe(FilteredRunner(device(pid="4EE7"), {})).probe()
    assert len(wrong_pid) == 1 and not wrong_pid[0].connected
    assert wrong_pid[0].mode == "no-device"

    wrong_name = SpdDiagnosticProbe(FilteredRunner(device(name="USB Composite Device"), {})).probe()
    assert len(wrong_name) == 1 and not wrong_name[0].connected
    assert wrong_name[0].mode == "no-device"


def test_host_helper_cannot_claim_download_or_force_connection(monkeypatch):
    monkeypatch.setenv("TTG_SPD_DIAGNOSTIC_HELPER", "mock-helper")

    good = SpdDiagnosticProbe(FilteredRunner(
        device(), {"connected": True, "mode": "download"}
    )).probe()
    assert len(good) == 1 and good[0].connected
    assert good[0].mode == "diagnostic"
    assert good[0].capabilities["transport_confirmed"]
    assert good[0].capabilities["download_mode_confirmed_by_usb"] is False
    assert good[0].capabilities["fdl_sent"] is False

    # Even if a helper invents an endpoint after an inventory miss, no device is admitted.
    missing = SpdDiagnosticProbe(FilteredRunner(
        device(name="Unisoc Android ADB", pid="4EE7"),
        {"connected": True, "mode": "download"}
    )).probe()
    assert len(missing) == 1 and not missing[0].connected
    assert missing[0].mode == "no-device"
