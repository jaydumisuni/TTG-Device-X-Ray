# MTK META read-only helper contract

`MtkMetaProbe` detects MediaTek USB transport directly through Windows PnP:

- `VID_0E8D&PID_2000` — Preloader
- `VID_0E8D&PID_2007` — Kernel META

VID/PID and COM-port evidence works without a helper. The proven D2e/TSM DLL session plugs in through an external read-only helper so Device X-Ray does not hard-code vendor DLL paths or unstable export signatures.

## Configure

```powershell
$env:TTG_MTK_META_HELPER='D:\aimob\hunter\venv\Scripts\python.exe D:\projects\TTG-META\ttg_mtk_meta_probe_helper.py'
ttg-xray scan --output scans
```

X-Ray calls the configured helper with:

```text
--probe-json
--read-only
--pid 2000|2007
--pnp-device-id <Windows PNPDeviceID>
--port COMx                 # when a COM port is visible
```

The helper must initialize the existing vendor session in read-only mode. The known D2e path can perform `_InitMtkDll`, `_SPMeta_Preloader_BootMode`, attach to PID 2007, then read target/version/storage/GPT evidence. It must not invoke factory reset, FRP removal, write, format, or destructive service exports.

## Required JSON output

The final non-empty stdout line must be one JSON object:

```json
{
  "connected": true,
  "mode": "meta",
  "identifiers": {
    "brand": "TECNO",
    "manufacturer": "TECNO MOBILE LIMITED",
    "model_code": "CM6",
    "platform": "MT6789",
    "chipset": "MT6789",
    "android_version": "13",
    "build_id": "CM6-H8123",
    "security_patch": "2024-01-05",
    "imei": "REDACTED_OR_OPERATOR_ALLOWED",
    "preloader_version": "...",
    "modem_version": "...",
    "storage_type": "UFS",
    "storage_model": "...",
    "storage_capacity_bytes": "128000000000"
  },
  "capabilities": {
    "dll_session_initialized": true,
    "preloader_boot_mode_return": 0,
    "target_info_read": true,
    "partition_map_read": true,
    "read_only": true,
    "storage": {
      "type": "UFS",
      "model": "...",
      "capacity_bytes": 128000000000,
      "logical_block_size": 4096
    }
  },
  "partitions": [
    {
      "name": "proinfo",
      "storage_region": "UFS_LUN0",
      "start_sector": 123456,
      "sector_count": 768,
      "logical_block_size": 4096,
      "size_bytes": 3145728
    }
  ],
  "warnings": []
}
```

## Offline evidence replay

A previously captured JSON object can be replayed without hardware:

```powershell
$env:TTG_MTK_META_EVIDENCE_FILE='fixtures\mtk_meta\cm6-meta.json'
ttg-xray scan --output scans
```

This is intended for fixtures, regression tests, profile development, and Code Agent review.

## Safety boundary

The helper is an observation adapter. A successful META connection does not authorize a write. Device X-Ray always emits `write_allowed: false`; a separately reviewed repair executor must consume the certified evidence package.
