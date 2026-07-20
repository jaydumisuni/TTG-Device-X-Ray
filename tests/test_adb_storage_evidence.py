from ttg_device_xray.transports.adb import AdbProbe


def test_storage_inventory_recognizes_android_ufs_lun() -> None:
    devices = AdbProbe._parse_storage_inventory(
        "sda|244277248|4096|H9HQ15AECMMDAR|0\n"
    )

    assert len(devices) == 1
    assert devices[0]["type"] == "UFS"
    assert devices[0]["capacity_bytes"] == 244277248 * 512
    assert devices[0]["logical_block_size"] == 4096
    assert devices[0]["model"] == "H9HQ15AECMMDAR"


def test_storage_type_can_be_inferred_from_partition_backing_device() -> None:
    inferred = AdbProbe._infer_storage_from_partitions(
        [
            {
                "name": "boot_a",
                "target": "/dev/block/sda17",
                "block_device": "sda17",
            },
            {
                "name": "super",
                "target": "/dev/block/sda29",
                "block_device": "sda29",
            },
        ]
    )

    assert inferred["type"] == "UFS"
    assert inferred["capacity_bytes"] == 0
    assert inferred["source"] == "adb-partition-backing-device"


def test_by_name_fallback_keeps_backing_block_name() -> None:
    partitions = AdbProbe._parse_by_name(
        "lrwxrwxrwx 1 root root 21 boot_a -> /dev/block/sda17\n"
    )

    assert partitions[0]["name"] == "boot_a"
    assert partitions[0]["block_device"] == "sda17"
