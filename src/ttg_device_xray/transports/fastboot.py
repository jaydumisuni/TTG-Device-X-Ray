from __future__ import annotations

from ..command import Runner
from ..models import TransportKind, TransportObservation


class FastbootProbe:
    name = "fastboot"

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def probe(self) -> list[TransportObservation]:
        if not self.runner.exists("fastboot"):
            return [
                TransportObservation(
                    transport=TransportKind.FASTBOOT,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=["fastboot executable was not found"],
                )
            ]

        listing = self.runner.run(["fastboot", "devices"])
        observations: list[TransportObservation] = []
        for line in listing.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            serial = parts[0]
            all_vars = self.runner.run(["fastboot", "-s", serial, "getvar", "all"], timeout=30)
            combined = "\n".join([all_vars.stdout, all_vars.stderr])
            identifiers = self._parse_vars(combined)
            observations.append(
                TransportObservation(
                    transport=TransportKind.FASTBOOT,
                    available=True,
                    connected=True,
                    mode="fastbootd" if identifiers.get("is-userspace") == "yes" else "fastboot",
                    identifiers={"serial": serial, **identifiers},
                    capabilities={
                        "unlocked": identifiers.get("unlocked") == "yes",
                        "slot_count": identifiers.get("slot-count", ""),
                    },
                    commands=[listing, all_vars],
                )
            )

        if not observations:
            observations.append(
                TransportObservation(
                    transport=TransportKind.FASTBOOT,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=[listing],
                )
            )
        return observations

    @staticmethod
    def _parse_vars(text: str) -> dict[str, str]:
        wanted = {
            "product",
            "variant",
            "serialno",
            "current-slot",
            "slot-count",
            "unlocked",
            "secure",
            "is-userspace",
            "version-bootloader",
            "version-baseband",
            "partition-type:super",
            "partition-size:super",
        }
        values: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip().removeprefix("(bootloader) ")
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key in wanted:
                values[key] = value.strip()
        return values
