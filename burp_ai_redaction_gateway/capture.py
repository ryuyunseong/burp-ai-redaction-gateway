from __future__ import annotations

import threading
import webbrowser
from pathlib import Path

from .dashboard import DashboardConfig, create_dashboard_server
from .receiver import ReceiverConfig, create_server


def run_capture(root: Path, receiver_port: int, dashboard_port: int, policy_path: Path | None, *, open_browser: bool) -> int:
    root.mkdir(parents=True, exist_ok=True)
    receiver = create_server("127.0.0.1", receiver_port, ReceiverConfig(
        output_dir=root / "burp_live", project="burp_live", policy_path=policy_path, complete_bundle=True,
    ))
    try:
        dashboard = create_dashboard_server("127.0.0.1", dashboard_port, DashboardConfig(root=root, policy_path=policy_path))
    except Exception:
        receiver.server_close()
        raise
    worker = threading.Thread(target=receiver.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{dashboard.server_address[1]}/burp"
    print(f"Burp 수신: http://127.0.0.1:{receiver.server_address[1]}/ingest/burp-history")
    print(f"점검 결과: {url}")
    print("Burp의 로컬 보안 점검 탭에서 자동 수집 시작을 누르세요. AI로 자동 전송하지 않습니다.")
    try:
        if open_browser:
            try:
                webbrowser.open(url, new=2)
            except (OSError, webbrowser.Error):
                print("브라우저를 열지 못했습니다. 위 주소를 직접 여세요.")
        dashboard.serve_forever()
    except KeyboardInterrupt:
        print("Burp 수신기와 대시보드를 종료했습니다.")
    finally:
        receiver.shutdown()
        receiver.server_close()
        worker.join(timeout=5)
        dashboard.server_close()
    return 0
