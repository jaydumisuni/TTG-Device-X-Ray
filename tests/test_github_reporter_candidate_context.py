from ttg_device_xray.github_reporter import safe_summary


def test_safe_summary_keeps_transport_context_without_identifiers() -> None:
    safe = safe_summary(
        {
            "scan_id": "xray-test",
            "candidate_count": 2,
            "selected_candidate_id": None,
            "verdict": "UNSAFE",
            "candidate_summaries": [
                {
                    "candidate_index": 1,
                    "link_confidence": 1.0,
                    "identity": {
                        "platform": "android",
                        "brand": "Redmi",
                        "manufacturer": "Xiaomi",
                        "marketing_model": "MODEL",
                        "internal_model": "device",
                        "board": "board",
                        "chipset": "soc",
                        "active_mode": "device",
                        "serial": "MUST-NOT-LEAK",
                    },
                    "observations": [
                        {
                            "transport": "adb",
                            "mode": "device",
                            "available": True,
                            "connected": True,
                            "usb_vid": "18D1",
                            "usb_pid": "4EE7",
                            "pnp_present": True,
                            "pnp_status": "OK",
                            "transport_confirmed": True,
                            "helper_configured": False,
                            "partition_count": 112,
                            "warning_count": 0,
                            "pnp_device_id": "MUST-NOT-LEAK",
                            "serial": "MUST-NOT-LEAK",
                            "usb_name": "MUST-NOT-LEAK",
                        }
                    ],
                }
            ],
            "profile_match": {"status": "NO_SELECTION"},
        },
        exit_code=2,
    )

    candidate = safe["candidate_summaries"][0]
    observation = candidate["observations"][0]

    assert candidate["identity"]["brand"] == "Redmi"
    assert "serial" not in candidate["identity"]
    assert observation["transport"] == "adb"
    assert observation["usb_vid"] == "18D1"
    assert observation["usb_pid"] == "4EE7"
    assert observation["partition_count"] == 112
    assert "pnp_device_id" not in observation
    assert "serial" not in observation
    assert "usb_name" not in observation
