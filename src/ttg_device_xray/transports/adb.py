from __future__ import annotations

import re
from typing import Any

from ..command import Runner
from ..models import TransportKind, TransportObservation


class AdbProbe:
    """Read-only Android probe with identity, storage and partition intelligence."""

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
        "baseband": "gsm.version.baseband",
        "bootloader": "ro.bootloader",
        "kernel": "ro.kernel.version",
        "verified_boot_state": "ro.boot.verifiedbootstate",
        "flash_locked": "ro.boot.flash.locked",
        "vbmeta_state": "ro.boot.vbmeta.device_state",
        "dynamic_partitions": "ro.boot.dynamic_partitions",
        "super_partition": "ro.boot.super_partition",
        "first_api_level": "ro.product.first_api_level",
        "vndk": "ro.vndk.version",
        "crypto_state": "ro.crypto.state",
        "treble": "ro.treble.enabled",
    }

    PARTITION_SCRIPT = r'''for p in /dev/block/by-name/*; do
n=${p##*/}; t=$(readlink -f "$p" 2>/dev/null); [ -n "$t" ] || continue
b=${t##*/}; s=$(cat "/sys/class/block/$b/size" 2>/dev/null); l=$(cat "/sys/class/block/$b/queue/logical_block_size" 2>/dev/null); r=$(cat "/sys/class/block/$b/ro" 2>/dev/null)
printf '%s|%s|%s|%s|%s|%s\n' "$n" "$p" "$t" "$s" "$l" "$r"
done'''

    STORAGE_SCRIPT = r'''for b in mmcblk0 sda sdb nvme0n1; do
p="/sys/class/block/$b"; [ -e "$p" ] || continue
s=$(cat "$p/size" 2>/dev/null); l=$(cat "$p/queue/logical_block_size" 2>/dev/null)
m=$(cat "$p/device/model" 2>/dev/null || cat "$p/device/name" 2>/dev/null)
t=$(cat "$p/device/type" 2>/dev/null)
printf '%s|%s|%s|%s|%s\n' "$b" "$s" "$l" "$m" "$t"
done'''

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def _adb(self, serial: str, *args: str, timeout: int = 20):
        return self.runner.run(["adb", "-s", serial, *args], timeout=timeout)

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

            uname = self._adb(serial, "shell", "uname", "-a")
            shell_id = self._adb(serial, "shell", "id")
            su_id = self._adb(serial, "shell", "su", "-c", "id")
            observation.commands.extend([uname, shell_id, su_id])
            if uname.return_code == 0 and uname.stdout:
                observation.identifiers["kernel"] = uname.stdout.strip()
            observation.capabilities.update(
                {
                    "authorized": True,
                    "shell_root": "uid=0" in shell_id.stdout,
                    "su_root": su_id.return_code == 0 and "uid=0" in su_id.stdout,
                    "verified_boot_state": observation.identifiers.get(
                        "verified_boot_state", ""
                    ),
                    "bootloader_locked": self._bootloader_locked(
                        observation.identifiers
                    ),
                }
            )

            partition_evidence = self._adb(
                serial, "shell", "sh", "-c", self.PARTITION_SCRIPT, timeout=30
            )
            observation.commands.append(partition_evidence)
            if partition_evidence.return_code == 0 and partition_evidence.stdout:
                observation.partitions = self._parse_partition_inventory(
                    partition_evidence.stdout
                )
            else:
                by_name = self._adb(serial, "shell", "ls", "-l", "/dev/block/by-name")
                observation.commands.append(by_name)
                if by_name.return_code == 0:
                    observation.partitions = self._parse_by_name(by_name.stdout)
                else:
                    observation.warnings.append("/dev/block/by-name was not readable")

            storage_evidence = self._adb(
                serial, "shell", "sh", "-c", self.STORAGE_SCRIPT
            )
            observation.commands.append(storage_evidence)
            storage = self._parse_storage_inventory(storage_evidence.stdout)
            if storage:
                primary = self._select_primary_storage(storage)
                observation.capabilities["storage_devices"] = storage
                observation.capabilities["storage"] = primary
                observation.identifiers["storage_type"] = primary.get("type", "")
                observation.identifiers["storage_model"] = primary.get("model", "")
                observation.identifiers["storage_capacity_bytes"] = str(
                    primary.get("capacity_bytes", 0)
                )

            mounts = self._adb(serial, "shell", "cat", "/proc/mounts")
            observation.commands.append(mounts)
            if mounts.return_code == 0:
                self._attach_mounts(observation.partitions, mounts.stdout)

            lpdump = self._adb(serial, "shell", "lpdump", timeout=30)
            observation.commands.append(lpdump)
            if lpdump.return_code == 0 and lpdump.stdout:
                logical = self._parse_lpdump(lpdump.stdout)
                observation.capabilities["logical_partitions"] = logical
                observation.capabilities["dynamic_partitions_detected"] = bool(logical)
            else:
                observation.capabilities["dynamic_partitions_detected"] = self._truthy(
                    observation.identifiers.get("dynamic_partitions", "")
                ) or any(item.get("name") == "super" for item in observation.partitions)

            observation.capabilities["partition_count"] = len(observation.partitions)
            observation.capabilities["ab_slots"] = self._has_ab_slots(
                observation.partitions,
                observation.identifiers.get("slot_suffix", ""),
            )
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
    def _truthy(value: str) -> bool:
        return value.strip().lower() in {"1", "true", "yes", "y"}

    @staticmethod
    def _bootloader_locked(ids: dict[str, str]) -> bool | None:
        if ids.get("vbmeta_state", "").lower() == "unlocked":
            return False
        value = ids.get("flash_locked", "").strip()
        if value == "1":
            return True
        if value == "0":
            return False
        return None

    @staticmethod
    def _risk_for_partition(name: str) -> str:
        base = name.removesuffix("_a").removesuffix("_b").lower()
        critical = {
            "preloader", "xbl", "xbl_config", "abl", "bootloader", "lk",
            "gpt", "pgpt", "sgpt", "proinfo", "nvram", "nvdata", "persist",
            "efs", "modem", "md1img", "super", "vbmeta", "boot", "vendor_boot",
        }
        sensitive = {"frp", "metadata", "userdata", "misc", "dtbo", "recovery"}
        if base in critical:
            return "critical"
        if base in sensitive:
            return "sensitive"
        return "normal"

    @classmethod
    def _parse_partition_inventory(cls, text: str) -> list[dict[str, Any]]:
        partitions: list[dict[str, Any]] = []
        for line in text.splitlines():
            parts = line.strip().split("|")
            if len(parts) != 6:
                continue
            name, path, target, sectors, block_size, read_only = parts
            sector_count = int(sectors) if sectors.isdigit() else 0
            logical = int(block_size) if block_size.isdigit() else 512
            partitions.append(
                {
                    "name": name,
                    "path": path,
                    "target": target,
                    "block_device": target.rsplit("/", 1)[-1],
                    "sector_count": sector_count,
                    "logical_block_size": logical,
                    "size_bytes": sector_count * logical,
                    "read_only": read_only == "1",
                    "slot": cls._slot_for_name(name),
                    "risk": cls._risk_for_partition(name),
                    "source": "adb-sysfs-by-name",
                }
            )
        return sorted(partitions, key=lambda item: item["name"])

    @classmethod
    def _parse_by_name(cls, text: str) -> list[dict[str, Any]]:
        partitions: list[dict[str, Any]] = []
        pattern = re.compile(r"\s(?P<name>[^\s]+)\s+->\s+(?P<target>.+)$")
        for line in text.splitlines():
            match = pattern.search(line)
            if match:
                name = match.group("name")
                partitions.append(
                    {
                        "name": name,
                        "path": f"/dev/block/by-name/{name}",
                        "target": match.group("target").strip(),
                        "size_bytes": 0,
                        "slot": cls._slot_for_name(name),
                        "risk": cls._risk_for_partition(name),
                        "source": "adb-by-name",
                    }
                )
        return partitions

    @staticmethod
    def _parse_storage_inventory(text: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for line in text.splitlines():
            fields = line.strip().split("|")
            if len(fields) != 5:
                continue
            block, sectors, logical, model, raw_type = fields
            sector_count = int(sectors) if sectors.isdigit() else 0
            block_size = int(logical) if logical.isdigit() else 512
            lowered = " ".join([block, model, raw_type]).lower()
            if "mmc" in lowered:
                storage_type = "eMMC"
            elif block.startswith("sd") or "ufs" in lowered:
                storage_type = "UFS"
            elif block.startswith("nvme"):
                storage_type = "NVMe"
            else:
                storage_type = raw_type or "unknown"
            result.append(
                {
                    "block": block,
                    "sector_count": sector_count,
                    "logical_block_size": block_size,
                    "capacity_bytes": sector_count * block_size,
                    "model": model.strip(),
                    "type": storage_type,
                }
            )
        return result

    @staticmethod
    def _select_primary_storage(items: list[dict[str, Any]]) -> dict[str, Any]:
        return max(items, key=lambda item: int(item.get("capacity_bytes", 0)))

    @staticmethod
    def _attach_mounts(partitions: list[dict[str, Any]], text: str) -> None:
        by_target = {item.get("target"): item for item in partitions}
        by_name = {item.get("name"): item for item in partitions}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            source, mountpoint, filesystem = fields[:3]
            candidate = by_target.get(source)
            if candidate is None:
                candidate = by_name.get(source.rsplit("/", 1)[-1])
            if candidate is not None:
                candidate["mountpoint"] = mountpoint
                candidate["filesystem"] = filesystem

    @staticmethod
    def _parse_lpdump(text: str) -> list[dict[str, Any]]:
        logical: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("Name:"):
                if current and current.get("name"):
                    logical.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif current is not None and line.startswith("Group:"):
                current["group"] = line.split(":", 1)[1].strip()
            elif current is not None and line.startswith("Attributes:"):
                current["attributes"] = line.split(":", 1)[1].strip()
            elif current is not None and line.startswith("Extent"):
                current["extent_count"] = int(current.get("extent_count", 0)) + 1
        if current and current.get("name"):
            logical.append(current)
        return logical

    @staticmethod
    def _slot_for_name(name: str) -> str:
        if name.endswith("_a"):
            return "a"
        if name.endswith("_b"):
            return "b"
        return ""

    @staticmethod
    def _has_ab_slots(partitions: list[dict[str, Any]], suffix: str) -> bool:
        if suffix in {"_a", "_b", "a", "b"}:
            return True
        names = {str(item.get("name", "")) for item in partitions}
        return any(name.endswith("_a") and f"{name[:-2]}_b" in names for name in names)
