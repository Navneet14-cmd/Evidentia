"""GUI entry point."""
from __future__ import annotations

import sys


def main(argv=None) -> int:
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from ..forensic.service import Evidentia
    from .main_window import MainWindow
    from .state import AppState
    from .theme import QSS

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("Evidentia")
    app.setOrganizationName("Evidentia")
    app.setStyle("Fusion")
    f = QFont()
    f.setPointSize(13 if sys.platform == "darwin" else 10)
    app.setFont(f)
    app.setStyleSheet(QSS)
    state = AppState(Evidentia())
    win = MainWindow(state)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
