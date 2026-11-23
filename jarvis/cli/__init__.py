"""Command line interface.

Split into a package so a subcommand group can be read and changed
without loading the whole surface: `output` renders, `commands/*`
implement, `parser` wires them to argparse.
"""

from .output import C, color
from .parser import build_parser, main

__all__ = ["C", "color", "build_parser", "main"]
