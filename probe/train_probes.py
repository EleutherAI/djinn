#!/usr/bin/env python3
"""Shim script that forwards to djinn.probe.train_probes."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from djinn.probe.train_probes import main as real_main

    real_main()


if __name__ == "__main__":
    main()
