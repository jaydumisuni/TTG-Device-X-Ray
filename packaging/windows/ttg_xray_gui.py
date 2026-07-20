import os

os.environ.setdefault("TTG_XRAY_REPORT_REPO", "jaydumisuni/tools-test-repo")

from ttg_device_xray.qt_app import main


if __name__ == "__main__":
    raise SystemExit(main())
