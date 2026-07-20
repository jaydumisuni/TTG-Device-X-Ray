from ttg_device_xray.transports.adb import AdbProbe
from ttg_device_xray.transports.apple import AppleProbe
from ttg_device_xray.transports.fastboot import FastbootProbe


def test_adb_partition_parser():
    text = """
lrwxrwxrwx 1 root root 21 2026-01-01 00:00 proinfo -> /dev/block/mmcblk0p5
lrwxrwxrwx 1 root root 22 2026-01-01 00:00 super -> /dev/block/mmcblk0p40
"""
    result = AdbProbe._parse_by_name(text)
    assert [item["name"] for item in result] == ["proinfo", "super"]
    assert result[0]["risk"] == "critical"


def test_adb_inventory_calculates_bytes_and_slots():
    text = "boot_a|/dev/block/by-name/boot_a|/dev/block/sda12|4096|4096|0\n"
    result = AdbProbe._parse_partition_inventory(text)
    assert result[0]["size_bytes"] == 4096 * 4096
    assert result[0]["slot"] == "a"


def test_storage_parser_detects_ufs():
    result = AdbProbe._parse_storage_inventory("sda|1000|4096|UFS 3.1|disk\n")
    assert result[0]["type"] == "UFS"
    assert result[0]["capacity_bytes"] == 4_096_000


def test_fastboot_var_parser_reads_stderr_style_output():
    text = """
(bootloader) product: KM7
(bootloader) current-slot: a
(bootloader) unlocked: yes
(bootloader) partition-size:super: 0x100000
(bootloader) partition-type:super: raw
"""
    values, partitions = FastbootProbe._parse_vars(text)
    assert values["product"] == "KM7"
    assert values["unlocked"] == "yes"
    assert partitions[0]["name"] == "super"
    assert partitions[0]["size_bytes"] == 0x100000


def test_irecovery_parser():
    result = AppleProbe._parse_irecovery("CPID: 0x8015\nBDID: 0x0E\nMODE: DFU")
    assert result["CPID"] == "0x8015"
    assert result["MODE"] == "DFU"
