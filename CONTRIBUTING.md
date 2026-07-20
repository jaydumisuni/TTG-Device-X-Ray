# Contributing to TTG Device X-Ray

TTG Device X-Ray is a read-first device intelligence project. Contributions are welcome when they
preserve the evidence boundary and remain reproducible without customer hardware.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python scripts/run_local_checks.py
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Pull request requirements

A contribution should:

1. Keep device-facing discovery read-only.
2. Add or update deterministic tests.
3. Add synthetic fixture evidence when introducing a transport parser or profile.
4. Avoid real IMEI, ECID, UDID, serial, account, token, or customer information.
5. Keep profile-generated IDs separate from reviewed profile matches.
6. Preserve `write_allowed: false` in X-Ray models, profiles, fixtures, and outputs.
7. Pass `python scripts/run_local_checks.py`.

## Device profiles

Profiles belong under `src/ttg_device_xray/profiles/` or an external registry supplied through
`--profile-dir`. A profile is identification and planning evidence; it cannot authorize a repair.
Every profile must include a `safety` object with:

```json
{
  "read_only": true,
  "write_allowed": false,
  "profile_cannot_authorize_repairs": true
}
```

Use synthetic values in fixtures and document the source of structural evidence in the pull request.
Do not add raw customer dumps.

## Transport helpers

Helpers must accept `--probe-json` and `--read-only`, return structured JSON, and fail closed when the
requested evidence cannot be collected safely. Programmer uploads, FDL uploads, Odin/PIT writes,
partition writes, formats, resets, lock removal, activation operations, and firmware flashing do not
belong in this repository.

## Releases

Version tags use `vMAJOR.MINOR.PATCH`. The release gate requires the tag, `pyproject.toml`, and
`ttg_device_xray.__version__` to match before artifacts are published.
