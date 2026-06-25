#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""Backward-compatible launcher.

The CLI now lives in lib/cli.py and is also installed as the `pdive` console
script (see pyproject.toml). This shim keeps `python pdive++.py ...` working.
"""
from lib.cli import main

if __name__ == "__main__":
    main()
