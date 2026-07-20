import os

os.environ.setdefault("TTG_XRAY_REPORT_REPO", "jaydumisuni/tools-test-repo")

from ttg_device_xray.dev_updater import check_and_schedule_update
from ttg_device_xray.qt_app import main


if __name__ == "__main__":
    if check_and_schedule_update():
        raise SystemExit(0)
    raise SystemExit(main())
