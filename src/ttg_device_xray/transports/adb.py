from __future__ import annotations

import re

from ..command import Runner
from ..models import TransportKind, TransportObservation


class AdbProbe:
    name = "adb"

    PROPERTY_KEYS = {
        "brand": "ro.product.brand",
        "manufacturer": "ro.product.manufacturer",
        "model": "ro.product.model",
        "device": "ro.product.device",
        "product": "ro.product.name",
        "board": "ro.product.board",
        "soc": "ro.board.platform",
        "hardware": "ro.hardware",
        "android": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "build": "ro.build.display.id",
        "fingerprint": "ro.build.fingerprint",
        "security_patch": "ro.build.version.security_patch",
        "slot_suffix": "ro.boot.slot_suffix",
        "boot_device": "ro.boot.bootdevice",
    }

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def _adb(self, serial: str, *args: str):
        return self.runner.run(["adb", "-s", serial, *args])

    def probe(self) -> list[TransportObservation]:
        if not self.runner.exists("adb"):
            return [
                TransportObservation(
                    transport=TransportKind.ADB,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=["adb executable was not found"],
                )
            ]

        listing = self.runner.run(["adb", "devices", "-l"])
        observations: list[TransportObservation] = []
        rows = [line.strip() for line in listing.stdout.splitlines() if line.strip()]

        for row in rows:
            if row.startswith("List of devices") or row.startswith("*"):
                continue
            parts = row.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            observation = TransportObservation(
                transport=TransportKind.ADB,
                available=True,
                connected=state == "device",
                mode=state,
                identifiers={"serial": serial},
                commands=[listing],
            )
            if state != "device":
                observation.warnings.append(f"ADB device state is {state}")
                observations.append(observation)
                continue

            for key, prop_name in self.PROPERTY_KEYS.items():
                evidence = self._adb(serial, "shell", "getprop", prop_name)
                observation.commands.append(evidence)
                if evidence.return_code == 0 and evidence.stdout:
                    observation.identifiers[key] = evidence.stdout.strip()

            shell_id = self._adb(serial, "shell", "id")
            su_id = self._adb(serial, "shell", "su", "-c", "id")
            observation.commands.extend([shell_id, su_id])
            observation.capabilities.update(
                {
                    "authorized": True,
                    "shell_root": "uid=0" in shell_id.stdout,
                    "su_root": su_id.return_code == 0 and "uid=0" in su_id.stdout,
                }
            )

            by_name = self._adb(serial, "shell", "ls", "-l", "/dev/block/by-name")
            observation.commands.append(by_name)
            if by_name.return_code == 0:
                observation.partitions = self._parse_by_name(by_name.stdout)
            else:
                observation.warnings.append("/dev/block/by-name was not readable")

            storage = self._adb(serial, "shell", "cat", "/sys/class/block/mmcblk0/device/type")
            observation.commands.append(storage)
            if storage.return_code == 0 and storage.stdout:
                observation.identifiers["storage_type"] = storage.stdout.strip()

            observations.append(observation)

        if not observations:
            observations.append(
                TransportObservation(
                    transport=TransportKind.ADB,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=[listing],
                )
            )
        return observations

    @staticmethod
    def _parse_by_name(text: str) -> list[dict[str, str]]:
        partitions: list[dict[str, str]] = []
        pattern = re.compile(r"\s(?P<name>[^\s]+)\s+->\s+(?P<target>.+)$")
        for line in text.splitlines():
            match = pattern.search(line)
            if match:
                partitions.append(
                    {
                        "name": match.group("name"),
                        "path": f"/dev/block/by-name/{match.group('name')}",
                        "target": match.group("target").strip(),
                        "source": "adb-by-name",
                    }
                )
        return partitions
