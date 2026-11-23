import sys


def _never_die_on_output():
    """Console output must not be able to stop the program.

    On Windows a redirected stdout (a scheduled task, a service wrapper, the
    desktop app starting the daemon) uses the ANSI code page, so printing the
    startup banner's arrow raised UnicodeEncodeError and the daemon exited
    before it served anything. Unencodable text is now replaced, never fatal.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


_never_die_on_output()

from .cli import main  # noqa: E402  (after the stream guard on purpose)

sys.exit(main())
