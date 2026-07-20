from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, QThread, Qt, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QUrl

from .cli import main as cli_main

APP_NAME = "TTG Device X-Ray"
ORG_NAME = "THETECHGUY DIGITAL SOLUTIONS"


def runtime_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd().resolve()


def _looks_like_unlock_root(path: Path) -> bool:
    name = path.name.upper().replace("-", "_")
    return "TTG_UNLOCK" in name


def _unique_existing(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        key = str(resolved).lower()
        if key in seen or not resolved.exists():
            continue
        seen.add(key)
        result.append(resolved)
    return result


def find_unlock_roots() -> list[Path]:
    runtime = runtime_directory()
    anchors = [runtime, Path.cwd(), Path.home() / "Downloads"]
    if os.name == "nt":
        anchors.extend([Path("D:/All downloads"), Path("D:/projects")])

    candidates: list[Path] = []
    names = ("TTG_UNLOCK_V3", "TTG-UNLOCK", "TTG_UNLOCK")
    for anchor in anchors:
        candidates.append(anchor)
        candidates.extend(anchor / name for name in names)
        candidates.extend(anchor.parent / name for name in names)
        for parent in list(anchor.parents)[:3]:
            candidates.append(parent)
            candidates.extend(parent / name for name in names)

    roots = [path for path in _unique_existing(candidates) if _looks_like_unlock_root(path)]
    return roots


def default_output_directory() -> Path:
    configured = os.environ.get("TTG_UNLOCK_SCANS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()

    roots = find_unlock_roots()
    if roots:
        return roots[0] / "scans"

    return Path.home() / "Documents" / "THETECHGUY" / "TTG Device X-Ray" / "scans"


def configure_transport_path(output_directory: Path) -> list[Path]:
    roots = [runtime_directory(), Path.cwd(), output_directory.parent]
    roots.extend(find_unlock_roots())
    relative_locations = (
        Path("."),
        Path("platform-tools"),
        Path("tools"),
        Path("tools/platform-tools"),
        Path("tools/adb"),
        Path("bin"),
    )

    discovered: list[Path] = []
    for root in _unique_existing(roots):
        for relative in relative_locations:
            folder = root / relative
            if (folder / "adb.exe").exists() or (folder / "adb").exists():
                discovered.append(folder.resolve())

    if discovered:
        current = os.environ.get("PATH", "")
        prefix = os.pathsep.join(str(path) for path in _unique_existing(discovered))
        os.environ["PATH"] = prefix + os.pathsep + current
    return _unique_existing(discovered)


class ScanWorker(QObject):
    status = Signal(str)
    finished = Signal(int, str)

    def __init__(self, output_directory: Path) -> None:
        super().__init__()
        self.output_directory = output_directory

    @Slot()
    def run(self) -> None:
        stream = io.StringIO()
        try:
            self.output_directory.mkdir(parents=True, exist_ok=True)
            discovered = configure_transport_path(self.output_directory)
            if discovered:
                self.status.emit(f"ADB tools found in: {discovered[0]}")
            elif shutil.which("adb"):
                self.status.emit("ADB is available from the Windows PATH.")
            else:
                self.status.emit("ADB was not found. X-Ray will still test other transports.")

            self.status.emit("Scanning connected devices using read-only probes...")
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                code = cli_main(
                    [
                        "scan",
                        "--output",
                        str(self.output_directory),
                        "--no-hunter",
                    ]
                )
            self.finished.emit(int(code), stream.getvalue().strip())
        except BaseException:
            stream.write("\n")
            stream.write(traceback.format_exc())
            self.finished.emit(1, stream.getvalue().strip())


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None

        self.setWindowTitle(f"{APP_NAME} — Read-Only Device Intelligence")
        self.setMinimumSize(760, 570)
        self.resize(880, 650)
        self._build_ui()
        self._apply_style()
        self._load_output_directory()
        self._refresh_readiness()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(16)

        brand = QLabel("THETECHGUY DIGITAL SOLUTIONS")
        brand.setObjectName("Brand")
        title = QLabel("TTG DEVICE X-RAY")
        title.setObjectName("Title")
        subtitle = QLabel(
            "Read-first identification for Android and Apple repair workflows. "
            "X-Ray observes and certifies evidence; it does not perform destructive writes."
        )
        subtitle.setObjectName("Subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(brand)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        status_card = QFrame()
        status_card.setObjectName("Card")
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(16, 14, 16, 14)
        self.readiness_label = QLabel("Checking transport readiness...")
        self.readiness_label.setObjectName("Status")
        self.readiness_label.setWordWrap(True)
        status_layout.addWidget(self.readiness_label)
        layout.addWidget(status_card)

        output_card = QFrame()
        output_card.setObjectName("Card")
        output_layout = QVBoxLayout(output_card)
        output_layout.setContentsMargins(16, 14, 16, 14)
        output_title = QLabel("Scan output")
        output_title.setObjectName("SectionTitle")
        output_layout.addWidget(output_title)

        output_row = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Choose the TTG Unlock scans folder")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self._browse_output)
        output_row.addWidget(self.output_edit, 1)
        output_row.addWidget(browse_button)
        output_layout.addLayout(output_row)
        layout.addWidget(output_card)

        button_row = QHBoxLayout()
        self.scan_button = QPushButton("SCAN CONNECTED DEVICE")
        self.scan_button.setObjectName("PrimaryButton")
        self.scan_button.clicked.connect(self._start_scan)
        self.open_button = QPushButton("Open Scan Folder")
        self.open_button.clicked.connect(self._open_output)
        button_row.addWidget(self.scan_button, 1)
        button_row.addWidget(self.open_button)
        layout.addLayout(button_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        self.result_label = QLabel("Ready.")
        self.result_label.setObjectName("Result")
        layout.addWidget(self.result_label)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Scan details will appear here.")
        layout.addWidget(self.log, 1)

        self.setCentralWidget(root)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #090d13; color: #eaf2ff; }
            QLabel#Brand { color: #65d8ff; font-size: 11px; font-weight: 700; }
            QLabel#Title { color: white; font-size: 29px; font-weight: 800; }
            QLabel#Subtitle { color: #a9b7c9; font-size: 13px; }
            QLabel#SectionTitle { color: white; font-size: 13px; font-weight: 700; }
            QLabel#Status, QLabel#Result { color: #b9c9dc; font-size: 13px; }
            QFrame#Card { background: #111823; border: 1px solid #223145; border-radius: 10px; }
            QLineEdit, QTextEdit {
                background: #0c121b; border: 1px solid #29394f; border-radius: 7px;
                padding: 9px; color: #eaf2ff; selection-background-color: #147ea8;
            }
            QPushButton {
                background: #1a2635; border: 1px solid #334a64; border-radius: 7px;
                padding: 10px 14px; color: #eaf2ff; font-weight: 600;
            }
            QPushButton:hover { background: #22344a; }
            QPushButton:disabled { color: #6d7c8f; background: #151c26; }
            QPushButton#PrimaryButton {
                background: #0c85b6; border-color: #35c9ff; color: white;
                font-size: 14px; font-weight: 800; padding: 13px;
            }
            QPushButton#PrimaryButton:hover { background: #109bcf; }
            QProgressBar { border: 0; background: #151d28; height: 5px; border-radius: 2px; }
            QProgressBar::chunk { background: #35c9ff; border-radius: 2px; }
            """
        )

    def _load_output_directory(self) -> None:
        saved = str(self.settings.value("outputDirectory", "")).strip()
        selected = Path(saved) if saved else default_output_directory()
        self.output_edit.setText(str(selected))

    def _refresh_readiness(self) -> None:
        output = Path(self.output_edit.text().strip() or default_output_directory())
        configure_transport_path(output)
        adb = shutil.which("adb")
        unlock_roots = find_unlock_roots()
        adb_text = f"ADB: Ready ({adb})" if adb else "ADB: Not found"
        unlock_text = (
            f"TTG Unlock: {unlock_roots[0]}" if unlock_roots else "TTG Unlock: not auto-detected"
        )
        self.readiness_label.setText(f"{adb_text}\n{unlock_text}\nOutput: {output}")

    @Slot()
    def _browse_output(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose TTG Unlock scans folder",
            self.output_edit.text().strip(),
        )
        if selected:
            self.output_edit.setText(selected)
            self.settings.setValue("outputDirectory", selected)
            self._refresh_readiness()

    @Slot()
    def _open_output(self) -> None:
        output = Path(self.output_edit.text().strip() or default_output_directory())
        output.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(output.resolve())))

    @Slot()
    def _start_scan(self) -> None:
        output_text = self.output_edit.text().strip()
        if not output_text:
            QMessageBox.warning(self, APP_NAME, "Choose a scan output folder first.")
            return

        output = Path(output_text).expanduser()
        self.settings.setValue("outputDirectory", str(output))
        self.scan_button.setEnabled(False)
        self.output_edit.setEnabled(False)
        self.progress.setRange(0, 0)
        self.result_label.setText("Starting X-Ray...")
        self.log.clear()

        self.thread = QThread(self)
        self.worker = ScanWorker(output)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.status.connect(self._append_status)
        self.worker.finished.connect(self._scan_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(str)
    def _append_status(self, message: str) -> None:
        self.result_label.setText(message)
        self.log.append(message)

    @Slot(int, str)
    def _scan_finished(self, code: int, output: str) -> None:
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.scan_button.setEnabled(True)
        self.output_edit.setEnabled(True)
        self.log.setPlainText(output or "X-Ray completed without console output.")

        summary = self._parse_summary(output)
        if code == 0:
            verdict = summary.get("verdict", "COMPLETED")
            scan_id = summary.get("scan_id", "")
            self.result_label.setText(f"Scan complete — {verdict} {scan_id}".strip())
        elif code == 2:
            self.result_label.setText(
                "Scan bundle created, but the evidence verdict is UNSAFE. Review before repair."
            )
        else:
            self.result_label.setText("X-Ray scan failed. Review the details below.")

        self._refresh_readiness()
        self.worker = None
        self.thread = None

    @staticmethod
    def _parse_summary(output: str) -> dict[str, object]:
        if not output:
            return {}
        try:
            value = json.loads(output)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            start = output.find("{")
            end = output.rfind("}")
            if start >= 0 and end > start:
                try:
                    value = json.loads(output[start : end + 1])
                    return value if isinstance(value, dict) else {}
                except json.JSONDecodeError:
                    return {}
        return {}


def main() -> int:
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "THETECHGUY.DIGITAL_SOLUTIONS.TTGDeviceXRay"
            )
        except (AttributeError, OSError):
            pass

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
