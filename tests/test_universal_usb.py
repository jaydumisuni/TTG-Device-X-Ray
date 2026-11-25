"""Model-independent X-Ray USB inventory and evidence/candidate separation."""
from __future__ import annotations

import json

import pytest

from ttg_device_xray.candidate_grouping import ObservationGrouper
from ttg_device_xray.cli import _diagnostic_observation, build_parser
from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.models import CommandEvidence, TransportKind, TransportObservation
from ttg_device_xray.transports.universal_usb import UniversalUsbProbe


class Runner:
    def __init__(self, items, *, platform="windows", failed=False):
        self.items = items
        self.platform = platform
        self.failed = failed
        self.calls = []

    def exists(self, command):
        return command == ("powershell" if self.platform == "windows" else "lsusb")

    def run(self, command, timeout=20):
        self.calls.append(command)
        return CommandEvidence(
            command=command,
            return_code=1 if self.failed else 0,
            stdout=self.items if isinstance(self.items, str) else json.dumps(self.items),
            stderr="failed" if self.failed else "",
        )


def pnp(vid="F00D", pid="BEEF", name="Unknown Hardware (COM13)", cls="Ports",
        present=True):
    return {
        "InstanceId": f"USB\\VID_{vid}&PID_{pid}\\LAB000",
        "Name": name, "Class": cls, "Status": "OK", "Present": present,
    }


def test_unlisted_vendor_serial_device_is_discovered_without_model_profile():
    runner = Runner([pnp()])
    obs = UniversalUsbProbe(runner).probe()
    assert len(obs) == 1
    item = obs[0]
    assert item.transport == TransportKind.USB_INVENTORY
    assert item.connected and item.mode == "usb-selected"
    assert item.identifiers["usb_vid"] == "F00D"
    assert item.identifiers["usb_pid"] == "BEEF"
    assert item.identifiers["port"] == "COM13"
    assert item.capabilities["os_interface_class"] == "serial"
    assert item.capabilities["usb_present"] is True
    assert item.capabilities["transport_confirmed"] is False
    assert item.capabilities["protocol_verified"] is False
    assert item.capabilities["write_allowed"] is False
    assert item.capabilities["serial_port_opened"] is False
    assert len(runner.calls) == 1
    assert "Get-PnpDevice" in runner.calls[0][-1]
    assert "VID_F00D" not in runner.calls[0][-1]


def test_host_peripherals_remain_visible_but_not_device_candidates():
    devices = [
        pnp("1ABC", "0001", "Integrated webcam", "Camera"),
        pnp("1ABC", "0002", "Generic keyboard", "HIDClass"),
        pnp("1ABC", "0003", "USB root hub", "USB"),
        pnp("1ABC", "0004", "Portable player", "WPD"),
    ]
    obs = UniversalUsbProbe(Runner(devices)).probe()
    assert len(obs) == 4
    assert [item.connected for item in obs] == [False, False, False, True]
    bundle = EnhancedXRayPipeline([UniversalUsbProbe(Runner(devices))]).scan()
    assert len(bundle.observations) == 4
    assert len(bundle.candidates) == 1
    assert not bundle.certification.write_allowed
    assert bundle.identity.platform == "unknown"


def test_unknown_vendor_usb_can_be_explicitly_selected_without_protocol_inference():
    device = pnp("C0DE", "2026", "Vendor-specific USB interface", "USB")
    generic = UniversalUsbProbe(Runner(device)).probe()[0]
    assert generic.capabilities["usb_present"] and not generic.connected
    selected = UniversalUsbProbe(
        Runner(device), target_usb=("c0de:2026",)
    ).probe()[0]
    assert selected.connected
    assert selected.capabilities["selected_explicitly"] is True
    assert selected.capabilities["protocol_verified"] is False
    assert selected.capabilities["download_mode_confirmed_by_usb"] is False
    result = EnhancedXRayPipeline(
        [UniversalUsbProbe(Runner(device), target_usb=("C0DE:2026",))]
    ).scan()
    assert len(result.candidates) == 1
    assert result.identity.platform == "unknown"
    assert result.identity.firmware_version == ""
    assert not result.certification.write_allowed


def test_invalid_selector_is_rejected_before_device_probing():
    for selector in ("C0DE", "C0DE:2026;del all", "0xC0DE:2026", "",
                     "12345:6789"):
        with pytest.raises(ValueError, match="VID:PID"):
            UniversalUsbProbe(Runner([]), target_usb=(selector,))


def test_linux_lists_all_usb_inventory_and_explicitly_targets_unknown():
    listing = "\n".join([
        "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub",
        "Bus 001 Device 002: ID 1234:ABCD Unrecognized service hardware",
        "Bus 001 Device 003: ID 9876:1234 USB camera",
    ])
    inventory = UniversalUsbProbe(Runner(listing, platform="linux")).probe()
    assert len(inventory) == 3
    assert all(item.capabilities["usb_present"] for item in inventory)
    assert all(not item.connected for item in inventory)
    selected = UniversalUsbProbe(
        Runner(listing, platform="linux"), target_usb=("1234:ABCD",)
    ).probe()
    assert [item.connected for item in selected] == [False, True, False]
    assert selected[1].identifiers["usb_path"] == "bus-001-device-002"
    assert selected[1].capabilities["protocol_verified"] is False


def test_usb_presence_does_not_create_candidate_for_ghost_or_failure():
    ghost = UniversalUsbProbe(Runner([pnp(present=False)])).probe()
    assert len(ghost) == 1 and not ghost[0].connected
    fail = UniversalUsbProbe(Runner([], failed=True)).probe()
    assert len(fail) == 1 and fail[0].mode == "inventory-failed"
    assert not fail[0].available and not fail[0].connected


def test_inventory_observation_can_link_to_protocol_probe_by_exact_pnp_identity():
    item = UniversalUsbProbe(Runner(pnp())).probe()[0]
    specialist = TransportObservation(
        transport=TransportKind.QUALCOMM_EDL,
        available=True, connected=True, mode="edl",
        identifiers={"pnp_device_id": item.identifiers["pnp_device_id"]},
    )
    groups = ObservationGrouper.group([item, specialist])
    assert len(groups) == 1
    assert len(groups[0].observations) == 2
    assert groups[0].link_confidence == 1.0


def test_cli_supports_manual_usb_targeting_and_hides_raw_device_id():
    args = build_parser().parse_args([
        "scan", "--target-usb", "C0DE:2026", "--target-usb", "F00D:BEEF",
    ])
    assert args.target_usb == ["C0DE:2026", "F00D:BEEF"]
    item = UniversalUsbProbe(Runner(pnp())).probe()[0]
    compact = _diagnostic_observation(item)
    assert compact["transport"] == "usb_inventory"
    assert compact["usb_vid"] == "F00D"
    assert "pnp_device_id" not in compact
    assert "port" not in compact
    assert "usb_name" not in compact


def test_identical_vid_pid_devices_are_separately_selectable_by_hashed_token():
    first = pnp("ACDC", "1010", "Unknown interface", "USB")
    second = {**first, "InstanceId": r"USB\VID_ACDC&PID_1010\LAB999"}
    records = UniversalUsbProbe(Runner([first, second])).probe()
    assert len(records) == 2
    assert records[0].identifiers["inventory_id"] != records[1].identifiers["inventory_id"]
    assert all(not item.connected for item in records)
    selected = UniversalUsbProbe(
        Runner([first, second]),
        target_device=(records[1].identifiers["inventory_id"],),
    ).probe()
    assert [item.connected for item in selected] == [False, True]
    assert all(item.capabilities["protocol_verified"] is False for item in selected)


def test_invalid_inventory_token_fails_closed():
    with pytest.raises(ValueError, match="16-digit inventory ID"):
        UniversalUsbProbe(
            Runner([pnp()]), target_device=("not-an-id",),
        )


def test_windows_get_cim_fallback_is_present_and_does_not_open_devices():
    runner = Runner([pnp()])
    UniversalUsbProbe(runner).probe()
    shell = runner.calls[0][-1]
    assert "Get-PnpDevice -PresentOnly" in shell
    assert "Get-CimInstance Win32_PnPEntity" in shell
    assert "Set-PnpDevice" not in shell
    assert "Enable-PnpDevice" not in shell
    assert "Disable-PnpDevice" not in shell


def test_truncated_inventory_is_disclosed_in_capabilities():
    records = [
        {**pnp("F00D", "BEEF", cls="Camera"),
         "InstanceId": f"USB\\VID_F00D&PID_BEEF\\LAB{i}"}
        for i in range(260)
    ]
    inventory = UniversalUsbProbe(Runner(records)).probe()
    assert len(inventory) == 256
    assert all(item.capabilities["inventory_truncated"] for item in inventory)
    assert any("256-entry" in warning for warning in inventory[0].warnings)
