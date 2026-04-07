#!/usr/bin/env python3
"""Compile the Verity-generated Merkle kernel Yul into deployable initcode."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


def _rewrite_shadowed_ite_names(yul_source: str) -> str:
    lines = yul_source.splitlines()
    depth = 0
    scopes: list[tuple[int, str]] = []
    counter = 0
    rewritten: list[str] = []

    for line in lines:
        if "__ite_cond" in line:
            if "let __ite_cond :=" in line:
                counter += 1
                fresh = f"__ite_cond_{counter}"
                scopes.append((depth, fresh))
                line = line.replace("__ite_cond", fresh)
            elif scopes:
                line = line.replace("__ite_cond", scopes[-1][1])
        rewritten.append(line)
        depth += line.count("{") - line.count("}")
        while scopes and scopes[-1][0] > depth:
            scopes.pop()

    return "\n".join(rewritten) + ("\n" if yul_source.endswith("\n") else "")


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

    try:
        result = subprocess.run(
            ["solc", "--strict-assembly", "--bin", str(yul_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        if "Variable name __ite_cond already taken in this scope" not in exc.stderr:
            raise
        with tempfile.TemporaryDirectory() as tmpdir:
            normalized = pathlib.Path(tmpdir) / "MerkleKernel.normalized.yul"
            normalized.write_text(_rewrite_shadowed_ite_names(yul_path.read_text(encoding="utf-8")),
                                  encoding="utf-8")
            result = subprocess.run(
                ["solc", "--strict-assembly", "--bin", str(normalized)],
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
