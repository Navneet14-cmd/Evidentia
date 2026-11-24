"""GUI entry point."""
from __future__ import annotations

import sys


def main(argv=None) -> int:
    from PySide6.QtWidgets import QApplication

    from ..forensic.service import Evidentia
    from .main_window import MainWindow
    from .state import AppState
    from . import theme

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("Evidentia")
    app.setOrganizationName("Evidentia")
    theme.apply(app)
    state = AppState(Evidentia())
    win = MainWindow(state)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
