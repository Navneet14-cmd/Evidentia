"""`python -m evidentia` launches the GUI; `python -m evidentia.cli ...` is the CLI."""
import sys

if len(sys.argv) > 1 and sys.argv[1] not in ("--gui",):
    from .cli import main
    sys.exit(main())

from .gui.app import main  # noqa: E402

sys.exit(main())
