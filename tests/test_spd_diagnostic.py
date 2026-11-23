"""Real SPRD U2S diagnostic USB VID/PID is presence-only, not download."""
from __future__ import annotations
import json
from ttg_device_xray.cli import _diagnostic_observation
from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.models import CommandEvidence, TransportKind
from ttg_device_xray.transports.spd_diagnostic import SpdDiagnosticProbe


class PnpRunner:
    def __init__(self,payload):self.payload=payload
    def exists(self,command):return command=="powershell"
    def run(self,command,timeout=20):
        return CommandEvidence(command=command,return_code=0,
                               stdout=json.dumps(self.payload),duration_ms=1)


def real_pnp():
    return {
      "Name":"SPRD U2S Diag (COM52)",
      "PNPDeviceID":r"USB\VID_1782&PID_4D00\5&242A2F40&0&5",
      "Status":"OK","Present":True,"ConfigManagerErrorCode":0,
    }


def test_exact_unisoc_diag_usb_is_connected_only_in_diagnostic_mode():
    probe=SpdDiagnosticProbe(PnpRunner(real_pnp()))
    observed=probe.probe()
    assert len(observed)==1
    info=observed[0]
    assert info.transport==TransportKind.SPD_DIAGNOSTIC
    assert info.connected
    assert info.mode=="diagnostic"
    assert info.identifiers["usb_vid"]=="1782"
    assert info.identifiers["usb_pid"]=="4D00"
    assert info.identifiers["port"]=="COM52"
    assert info.capabilities["diagnostic_port_confirmed_by_usb"]
    assert not info.capabilities["download_mode_confirmed_by_usb"]
    assert info.capabilities["read_only"] and not info.capabilities["fdl_sent"]
    assert not info.capabilities["serial_port_opened"]
    bundle=EnhancedXRayPipeline([probe]).scan()
    assert len(bundle.candidates)==1
    assert bundle.identity.active_mode=="diagnostic"
    assert bundle.identity.firmware_version==""
    assert not bundle.certification.write_allowed
    compact=_diagnostic_observation(info)
    assert compact["transport"]=="spd_diagnostic"
    assert "pnp_device_id" not in compact


def test_spd_diagnostic_cannot_be_promoted_by_normal_unisoc_vendor_hint():
    pnp={"Name":"Unisoc Android Composite ADB Interface",
         "PNPDeviceID":r"USB\VID_1782&PID_4EE7\NORMAL",
         "Present":True,"Status":"OK"}
    p=SpdDiagnosticProbe(PnpRunner(pnp))
    assert not p._verified_diag_endpoint(p._parse_windows_pnp(json.dumps(pnp))[0])
    records=p.probe()
    assert not records[0].connected
    assert records[0].mode=="unqualified-usb"


def test_diag_vid_pid_without_matching_port_label_not_download_or_diag():
    pnp=real_pnp()
    pnp["Name"]="USB Modem (COM52)"
    probe=SpdDiagnosticProbe(PnpRunner(pnp))
    parsed=probe._parse_windows_pnp(json.dumps(pnp))[0]
    assert not probe._verified_diag_endpoint(parsed)
    assert not probe._endpoint_confirms_transport(parsed,"diagnostic",
       {"diagnostic_port_confirmed_by_usb":True,"download_mode_confirmed_by_usb":False})


def test_ghost_device_does_not_count_as_live_candidate():
    pnp=real_pnp()
    pnp["Present"]=False
    pnp["ConfigManagerErrorCode"]=45
    r=SpdDiagnosticProbe(PnpRunner(pnp)).probe()
    assert len(r)==1 and not r[0].connected


def test_diag_probe_uses_only_usb_inventory_not_com_port_access():
    p=SpdDiagnosticProbe(PnpRunner(real_pnp()))
    o=p.probe()[0]
    assert o.connected
    assert len(o.commands)==1
    cmd=o.commands[0].command
    assert any("Get-PnpDevice" in part for part in cmd)
    assert "serial" not in " ".join(cmd).lower()
