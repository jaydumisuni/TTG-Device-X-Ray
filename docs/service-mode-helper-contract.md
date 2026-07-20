# Read-only service-mode helper contract

TTG Device X-Ray detects Qualcomm EDL, Spreadtrum/Unisoc download mode, and Samsung Download Mode
through local USB inventory. Optional helpers enrich the observation with protocol-specific identity,
storage and partition evidence.

## Environment variables

| Transport | Helper | Offline fixture |
|---|---|---|
| Qualcomm EDL | `TTG_QUALCOMM_EDL_HELPER` | `TTG_QUALCOMM_EDL_EVIDENCE_FILE` |
| Spreadtrum/Unisoc | `TTG_SPD_HELPER` | `TTG_SPD_EVIDENCE_FILE` |
| Samsung Download | `TTG_SAMSUNG_DOWNLOAD_HELPER` | `TTG_SAMSUNG_DOWNLOAD_EVIDENCE_FILE` |

## Arguments

The configured helper receives:

```text
--probe-json
--read-only
--transport qualcomm_edl|spd_download|samsung_download
--usb-vid <VID>
--usb-pid <PID>
--pnp-device-id <Windows PNPDeviceID>   # when available
--port COMx                             # when available
--usb-path <lsusb line/path>            # when available
```

The final non-empty stdout line must be one JSON object:

```json
{
  "connected": true,
  "mode": "edl",
  "identifiers": {
    "brand": "Example",
    "model_code": "MODEL",
    "chipset": "SOC",
    "serial": "OPTIONAL",
    "storage_type": "UFS",
    "storage_model": "OPTIONAL",
    "storage_capacity_bytes": "128000000000"
  },
  "capabilities": {
    "protocol_query_completed": true,
    "partition_map_read": true,
    "read_only": true,
    "storage": {
      "type": "UFS",
      "model": "OPTIONAL",
      "capacity_bytes": 128000000000,
      "logical_block_size": 4096
    }
  },
  "partitions": [
    {
      "name": "boot_a",
      "start_sector": 123456,
      "sector_count": 16384,
      "logical_block_size": 4096,
      "size_bytes": 67108864
    }
  ],
  "warnings": []
}
```

## Transport-specific limits

### Qualcomm EDL

The X-Ray helper may perform a non-destructive Sahara/Firehose identity query only where a reviewed
shop adapter already supports it. It must not upload an unverified programmer, erase, patch, reset,
or write GPT/partitions.

### Spreadtrum / Unisoc

The helper may report the USB/download handshake and already-available read-only target evidence. It
must not send an FDL solely to bypass authorization and must not erase, format or write partitions.

### Samsung Download Mode

The helper may report Download Mode identity and read-only protocol evidence. It must not flash Odin
packages, repartition, write PIT, change KG/RMM state, or send destructive commands.

## Offline replay

A fixture uses the same JSON shape and can be replayed without hardware. This supports regression
tests, profile creation, firmware correlation and Code Agent review.

## Safety boundary

A connected service transport is evidence, not authorization. Device X-Ray always emits
`write_allowed: false`. The final repair engine remains a separate reviewed executor.
