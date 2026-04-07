#!/usr/bin/env python3
"""Compile the Verity-generated Merkle kernel Yul into deployable initcode."""

from __future__ import annotations

import pathlib
import subprocess
import sys


def main() -> int:
    print_only = "--stdout" in sys.argv[1:]
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    yul_path = repo_root / "verity" / "artifacts" / "sphincs-kernel" / "MerkleKernel.yul"
    out_path = repo_root / "verity" / "artifacts" / "sphincs-kernel" / "MerkleKernel.bin"

    if not yul_path.exists():
        print(
            "missing Yul artifact: run `cd verity && lake exe verity-compiler "
            "--module SphincsKernel.MerkleKernel --deny-local-obligations "
            "--deny-axiomatized-primitives --output artifacts/sphincs-kernel` first",
            file=sys.stderr,
        )
        return 1

    result = subprocess.run(
        ["solc", "--strict-assembly", "--bin", str(yul_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    marker = "Binary representation:"
    if marker not in result.stdout:
        print("solc output did not contain deployment bytecode", file=sys.stderr)
        return 1

    bytecode = result.stdout.split(marker, 1)[1].strip().splitlines()[0].strip()
    if not bytecode:
        print("solc returned empty deployment bytecode", file=sys.stderr)
        return 1

    if print_only:
        print(f"0x{bytecode}")
        return 0

    out_path.write_text(bytecode, encoding="ascii")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
