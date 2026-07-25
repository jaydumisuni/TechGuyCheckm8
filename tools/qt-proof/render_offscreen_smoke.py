from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QLabel, QMainWindow, QVBoxLayout, QWidget


def main() -> int:
    output = Path("qt-proof-output")
    output.mkdir(exist_ok=True)
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = QMainWindow()
    window.resize(720, 360)
    root = QWidget()
    layout = QVBoxLayout(root)
    title = QLabel("Qt offscreen visual-proof runner")
    title.setStyleSheet("font-size:24px; font-weight:700; color:#d8c7ff;")
    status = QLabel("PASS — PyQt6 rendered a real widget tree on the hosted runner.")
    status.setStyleSheet("font-size:14px; color:#39e75f;")
    layout.addWidget(title)
    layout.addWidget(status)
    layout.addStretch()
    root.setStyleSheet("background:#030810; color:#eef2f8; padding:24px;")
    window.setCentralWidget(root)
    window.show()
    app.processEvents()
    screenshot = output / "qt-offscreen-smoke.png"
    if not window.grab().save(str(screenshot), "PNG"):
        raise RuntimeError("Could not save Qt screenshot")
    receipt = {
        "status": "PASS",
        "qt_platform": os.environ.get("QT_QPA_PLATFORM"),
        "screenshot": screenshot.name,
        "width": window.width(),
        "height": window.height(),
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
