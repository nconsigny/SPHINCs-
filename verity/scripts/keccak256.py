#!/usr/bin/env python3
"""Delegate to the vendored Verity helper so local compilation stays replayable."""

from pathlib import Path
import runpy
import sys

TARGET = Path(__file__).resolve().parents[3] / "verity-framework" / "scripts" / "keccak256.py"

if not TARGET.exists():
    raise SystemExit(f"Missing delegated script: {TARGET}")

sys.path.insert(0, str(TARGET.parent))
runpy.run_path(str(TARGET), run_name="__main__")
