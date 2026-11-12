"""Support running the CLI with ``python -m aliasvault_backup``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
