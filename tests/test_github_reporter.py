from __future__ import annotations

import json

from ttg_device_xray.github_reporter import (
    diagnostic_fingerprint,
    parse_summary,
    safe_summary,
    sanitize_console,
    should_report,
)


def _unsafe_summary() -> dict:
    return {
        "scan_id": "xray-test",
        "candidate_count": 3,
        "selected_candidate_id": None,
        "verdict": "UNSAFE",
        "confidence": 0.0,
        "certification_dimensions": {"identity_confidence": 0.0},
        "identity": {
            "platform": "android",
            "brand": "Example",
            "marketing_model": "Demo Phone",
            "serial": "SECRET-SERIAL-123",
            "imei": "123456789012345",
            "udid": "SECRET-UDID",
            "ecid": "SECRET-ECID",
        },
        "storage": {"partition_count": 0},
        "profile_match": {
            "status": "NO_SELECTION",
            "reasons": ["Select exactly one device candidate."],
            "mismatches": [],
            "write_allowed": False,
        },
        "hunter_delivery": {
            "attempted": False,
            "error": "disabled",
            "payload_file": "D:\\customer\\payload.json",
        },
        "bundle_seal": {
            "status": "UNSIGNED",
            "manifest": "D:\\customer\\bundle_manifest.json",
            "signature": "D:\\customer\\bundle_manifest.sig",
            "file_count": 37,
        },
        "output": "D:\\customer\\scans\\xray-test",
    }


def test_safe_summary_excludes_identifiers_and_paths() -> None:
    safe = safe_summary(_unsafe_summary(), 2)
    encoded = json.dumps(safe)

    assert "SECRET-SERIAL-123" not in encoded
    assert "123456789012345" not in encoded
    assert "SECRET-UDID" not in encoded
    assert "SECRET-ECID" not in encoded
    assert "D:\\customer" not in encoded
    assert safe["candidate_count"] == 3
    assert safe["profile_match"]["status"] == "NO_SELECTION"


def test_console_sanitizer_removes_paths_tokens_and_identifier_values() -> None:
    source = (
        "serial=ABC123 imei=123456789012345 token=github_pat_secret\n"
        "manifest D:\\Users\\Owner\\scan\\bundle.json\n"
        "other useful failure text"
    )
    cleaned = sanitize_console(source)

    assert "ABC123" not in cleaned
    assert "123456789012345" not in cleaned
    assert "github_pat_secret" not in cleaned
    assert "D:\\Users\\Owner" not in cleaned
    assert "other useful failure text" in cleaned


def test_fingerprint_is_stable_for_the_same_failure() -> None:
    safe = safe_summary(_unsafe_summary(), 2)
    first = diagnostic_fingerprint(safe, "same error")
    second = diagnostic_fingerprint(safe, "same error")

    assert first == second
    assert len(first) == 12


def test_parse_summary_accepts_text_appended_after_json() -> None:
    output = json.dumps(_unsafe_summary()) + "\n[AUTO-DIAGNOSTIC]\nissue created"
    parsed = parse_summary(output)

    assert parsed["scan_id"] == "xray-test"
    assert parsed["candidate_count"] == 3


def test_unsafe_or_nonzero_results_are_reportable() -> None:
    assert should_report(2, _unsafe_summary()) is True
    assert should_report(1, {}) is True
    assert should_report(0, {"verdict": "CERTIFIED"}) is False
