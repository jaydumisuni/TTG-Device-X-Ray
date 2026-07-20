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


def test_fastboot_var_parser_reads_stderr_style_output():
    text = """
(bootloader) product: KM7
(bootloader) current-slot: a
(bootloader) unlocked: yes
"""
    result = FastbootProbe._parse_vars(text)
    assert result["product"] == "KM7"
    assert result["unlocked"] == "yes"


def test_irecovery_parser():
    result = AppleProbe._parse_irecovery("CPID: 0x8015\nBDID: 0x0E\nMODE: DFU")
    assert result["CPID"] == "0x8015"
    assert result["MODE"] == "DFU"
