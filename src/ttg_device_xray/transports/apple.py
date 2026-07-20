from __future__ import annotations

from ..command import Runner
from ..models import TransportKind, TransportObservation


class AppleProbe:
    name = "apple"

    LOCKDOWN_KEYS = [
        "ProductType",
        "HardwareModel",
        "ProductVersion",
        "BuildVersion",
        "SerialNumber",
        "UniqueDeviceID",
        "InternationalMobileEquipmentIdentity",
        "DeviceName",
        "ActivationState",
        "BasebandVersion",
        "CPUArchitecture",
    ]

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def probe(self) -> list[TransportObservation]:
        observations: list[TransportObservation] = []
        observations.extend(self._probe_normal())
        observations.extend(self._probe_recovery())
        return observations

    def _probe_normal(self) -> list[TransportObservation]:
        if not self.runner.exists("idevice_id"):
            return [
                TransportObservation(
                    transport=TransportKind.APPLE_NORMAL,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=["idevice_id was not found"],
                )
            ]

        listing = self.runner.run(["idevice_id", "-l"])
        udids = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
        if not udids:
            return [
                TransportObservation(
                    transport=TransportKind.APPLE_NORMAL,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=[listing],
                )
            ]

        observations: list[TransportObservation] = []
        for udid in udids:
            identifiers = {"udid": udid}
            commands = [listing]
            if self.runner.exists("ideviceinfo"):
                for key in self.LOCKDOWN_KEYS:
                    evidence = self.runner.run(["ideviceinfo", "-u", udid, "-k", key])
                    commands.append(evidence)
                    if evidence.return_code == 0 and evidence.stdout:
                        identifiers[key] = evidence.stdout.strip()
            else:
                warning = "ideviceinfo was not found; identity detail is limited"
                observations.append(
                    TransportObservation(
                        transport=TransportKind.APPLE_NORMAL,
                        available=True,
                        connected=True,
                        mode="normal",
                        identifiers=identifiers,
                        commands=commands,
                        warnings=[warning],
                    )
                )
                continue

            observations.append(
                TransportObservation(
                    transport=TransportKind.APPLE_NORMAL,
                    available=True,
                    connected=True,
                    mode="normal",
                    identifiers=identifiers,
                    capabilities={
                        "paired_or_queryable": bool(identifiers.get("ProductType")),
                        "activation_state": identifiers.get("ActivationState", ""),
                    },
                    commands=commands,
                )
            )
        return observations

    def _probe_recovery(self) -> list[TransportObservation]:
        if not self.runner.exists("irecovery"):
            return [
                TransportObservation(
                    transport=TransportKind.APPLE_RECOVERY,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=["irecovery was not found"],
                )
            ]

        query = self.runner.run(["irecovery", "-q"])
        combined = "\n".join([query.stdout, query.stderr]).strip()
        if query.return_code != 0 or not combined:
            return [
                TransportObservation(
                    transport=TransportKind.APPLE_RECOVERY,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=[query],
                )
            ]

        identifiers = self._parse_irecovery(combined)
        mode_text = identifiers.get("MODE", "Recovery").lower()
        kind = TransportKind.APPLE_DFU if "dfu" in mode_text else TransportKind.APPLE_RECOVERY
        return [
            TransportObservation(
                transport=kind,
                available=True,
                connected=True,
                mode=mode_text,
                identifiers=identifiers,
                capabilities={"queryable": True},
                commands=[query],
            )
        ]

    @staticmethod
    def _parse_irecovery(text: str) -> dict[str, str]:
        identifiers: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            identifiers[key.strip().upper()] = value.strip()
        return identifiers
