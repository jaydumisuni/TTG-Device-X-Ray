from __future__ import annotations

import re
from typing import Any

from ..command import Runner
from ..models import TransportKind, TransportObservation


class FastbootProbe:
    name = "fastboot"

    def __init__(self, runner: Runner, *, deep: bool = False) -> None:
        self.runner = runner
        self.deep = deep

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
            all_vars = self.runner.run(
                ["fastboot", "-s", serial, "getvar", "all"], timeout=30
            )
            combined = "\n".join([all_vars.stdout, all_vars.stderr])
            identifiers, partitions = self._parse_vars(combined)
            commands = [listing, all_vars]
            if self.deep:
                fetch = self.runner.run(["fastboot", "-s", serial, "getvar", "max-fetch-size"])
                commands.append(fetch)
                match = re.search(r"max-fetch-size:\s*(0x[0-9a-fA-F]+|[0-9]+)",
                                  fetch.stdout + "\n" + fetch.stderr)
                if (fetch.return_code == 0 and match
                        and int(match.group(1), 16 if match.group(1).startswith("0x") else 10)):
                    identifiers["max-fetch-size"] = match.group(1)
                if not identifiers.get("model"):
                    model = self.runner.run(["fastboot", "-s", serial, "oem", "get-product-model"])
                    commands.append(model)
                    m = re.search(r"\(bootloader\)\s+HUAWEI\s+([A-Z0-9-]+)",
                                  model.stdout + "\n" + model.stderr, re.I)
                    if model.return_code == 0 and m:
                        identifiers.update(brand="Huawei", model=m.group(1),
                                           chipset=identifiers.get("product", ""))
                        build = self.runner.run(
                            ["fastboot", "-s", serial, "oem", "get-build-number"])
                        info = self.runner.run(["fastboot", "-s", serial, "oem", "get-bootinfo"])
                        commands.extend([build, info])
                        b = re.search(r"\(bootloader\)\s+([A-Z0-9][A-Z0-9()._-]+)",
                                      build.stdout + "\n" + build.stderr, re.I)
                        if build.return_code == 0 and b:
                            identifiers["build"] = b.group(1)
                        lock = re.search(r"Lock state is (unlock|lock)\b",
                                         info.stdout + "\n" + info.stderr, re.I)
                        if info.return_code == 0 and lock:
                            identifiers["unlocked"] = "yes" if lock.group(1).lower() == "unlock" else "no"
            unlocked = identifiers.get("unlocked") == "yes"
            secure = identifiers.get("secure") == "yes"
            observations.append(
                TransportObservation(
                    transport=TransportKind.FASTBOOT,
                    available=True,
                    connected=True,
                    mode="fastbootd" if identifiers.get("is-userspace") == "yes" else "fastboot",
                    identifiers={"serial": serial, **identifiers},
                    capabilities={
                        "unlocked": unlocked,
                        "bootloader_locked": not unlocked if identifiers.get("unlocked") else None,
                        "secure": secure,
                        "slot_count": identifiers.get("slot-count", ""),
                        "current_slot": identifiers.get("current-slot", ""),
                        "dynamic_partitions_detected": any(
                            item.get("name") == "super" for item in partitions
                        ),
                    },
                    partitions=partitions,
                    commands=commands,
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
    def _parse_size(value: str) -> int:
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return 0

    @classmethod
    def _parse_vars(cls, text: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
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
            "hw-revision",
            "anti",
            "max-download-size",
        }
        values: dict[str, str] = {}
        partition_values: dict[str, dict[str, Any]] = {}
        for raw in text.splitlines():
            line = raw.strip().removeprefix("(bootloader) ")
            if ":" not in line:
                continue
            if line.startswith("partition-size:"):
                remainder = line.removeprefix("partition-size:")
                if ":" not in remainder:
                    continue
                name, value = remainder.split(":", 1)
                partition_values.setdefault(name.strip(), {"name": name.strip()})[
                    "size_bytes"
                ] = cls._parse_size(value.strip())
                continue
            if line.startswith("partition-type:"):
                remainder = line.removeprefix("partition-type:")
                if ":" not in remainder:
                    continue
                name, value = remainder.split(":", 1)
                partition_values.setdefault(name.strip(), {"name": name.strip()})[
                    "filesystem"
                ] = value.strip()
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in wanted:
                values[key] = value

        partitions = []
        for name, item in sorted(partition_values.items()):
            item.update(
                {
                    "path": f"fastboot:{name}",
                    "slot": "a" if name.endswith("_a") else "b" if name.endswith("_b") else "",
                    "source": "fastboot-getvar",
                }
            )
            partitions.append(item)
        return values, partitions
