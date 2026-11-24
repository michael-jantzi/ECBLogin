"""Console entry point for the double-clickable portable executable."""

import sys

from ecb_login import main


if __name__ == "__main__":
    # Redirected Windows output can use a legacy code page. A Unicode USB path
    # must never turn a successful preflight into an encoding failure.
    sys.stdout.reconfigure(errors="backslashreplace")
    try:
        result = main()
    except SystemExit as exc:
        result = exc.code
        if isinstance(result, str):
            print(result, file=sys.stderr)
            result = 1
    if len(sys.argv) == 1 and sys.stdin.isatty():
        try:
            input("Press Enter to close this window ...")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(result)
