from __future__ import annotations

from ttg_device_xray.models import CommandEvidence
from ttg_device_xray.platform_tools import PlatformToolsRunner
from ttg_device_xray.transports.adb import AdbProbe


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def exists(self, executable: str) -> bool:
        return executable in {"adb", "fastboot"}

    def run(self, command: list[str], timeout: int = 20) -> CommandEvidence:
        self.commands.append(command)
        if command == ["adb", "devices"]:
            return CommandEvidence(
                command=command,
                return_code=0,
                stdout="List of devices attached\nABC123\tdevice\n",
            )
        if command[:5] == ["adb", "-s", "ABC123", "shell", "getprop"]:
            prop = command[-1]
            values = {
                "ro.product.brand": "TECNO",
                "ro.product.manufacturer": "TECNO MOBILE LIMITED",
                "ro.product.model": "CAMON",
                "ro.product.device": "TECNO-CM6",
                "ro.product.name": "CM6",
                "ro.board.platform": "mt6789",
                "ro.build.version.release": "13",
                "ro.build.fingerprint": "TECNO/CM6/test:user/release-keys",
            }
            return CommandEvidence(command=command, return_code=0, stdout=values.get(prop, ""))
        if command[-3:] == ["shell", "id"]:
            return CommandEvidence(command=command, return_code=0, stdout="uid=2000(shell)")
        return CommandEvidence(command=command, return_code=0, stdout="")


def test_platform_runner_uses_plain_adb_devices_like_mibu() -> None:
    fake = FakeRunner()
    runner = PlatformToolsRunner(fake, adb_executable="adb", fastboot_executable="fastboot")

    evidence = runner.run(["adb", "devices", "-l"])

    assert evidence.return_code == 0
    assert "ABC123\tdevice" in evidence.stdout
    assert fake.commands[0] == ["adb", "devices"]
    assert ["adb", "devices", "-l"] not in fake.commands


def test_adb_probe_creates_candidate_observation_from_normal_adb() -> None:
    fake = FakeRunner()
    runner = PlatformToolsRunner(fake, adb_executable="adb", fastboot_executable="fastboot")

    observations = AdbProbe(runner).probe()

    assert len(observations) == 1
    observation = observations[0]
    assert observation.connected is True
    assert observation.mode == "device"
    assert observation.identifiers["serial"] == "ABC123"
    assert observation.identifiers["brand"] == "TECNO"
    assert observation.identifiers["device"] == "TECNO-CM6"
    assert observation.identifiers["soc"] == "mt6789"
    assert fake.commands[0] == ["adb", "devices"]
    assert any(command[:3] == ["adb", "-s", "ABC123"] for command in fake.commands)


def test_adb_listing_merges_stderr_for_older_daemon_output() -> None:
    class StderrRunner(FakeRunner):
        def run(self, command: list[str], timeout: int = 20) -> CommandEvidence:
            self.commands.append(command)
            if command == ["adb", "devices"]:
                return CommandEvidence(
                    command=command,
                    return_code=0,
                    stdout="List of devices attached",
                    stderr="ABC123\tdevice",
                )
            return CommandEvidence(command=command, return_code=0, stdout="")

    fake = StderrRunner()
    runner = PlatformToolsRunner(fake, adb_executable="adb")

    evidence = runner.run(["adb", "devices", "-l"])

    assert "ABC123\tdevice" in evidence.stdout
