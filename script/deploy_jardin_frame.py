#!/usr/bin/env python3
"""
Deploy a hand-optimized JARDÍN frame account on ethrex.

Architecture: thin bytecode proxy + Solidity implementation via DELEGATECALL.
  - Proxy (~45 bytes runtime): forwards calldata → DELEGATECALL impl → APPROVE(0,0,3)
  - Impl (JardineroFrameAccount / JardinFrameAccount): JARDÍN Type 1/2 logic,
    slot map, dual verifiers. Slot layout is fixed across impls so the proxy
    stays agnostic to which PQ verifier lives in slot 0.
  - Storage lives in the proxy (DELEGATECALL context)

Storage layout (shared across frame-impl variants):
  slot 0: primary PQ verifier  (SPX | T0 | C11)
  slot 1: forscVerifier
  slot 2: masterPkSeed
  slot 3: masterPkRoot
  slot 4: owner

Frame data format: sigHash(32) || abi.encode(bytes jardinSig)
The proxy's fallback forwards this to the impl's fallback, which parses and verifies.

Usage:
  python3 script/deploy_jardin_frame.py --impl <addr> --verifier <addr> \\
    --forsc <addr> --seed <hex> --root <hex> [--rpc <url>] [--dev-key <hex>]

  `--spx` / `--c11` are accepted as aliases for `--verifier` (legacy).
"""

import sys, os, json, subprocess, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import keccak256, to_b32

DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def build_proxy_bytecode(impl_addr: str) -> bytes:
    """Build the DELEGATECALL proxy with mode-aware APPROVE.

    Runtime pseudocode:
        if calldatasize == 0: STOP (receive ETH)
        CALLDATACOPY(0, 0, calldatasize)
        success = DELEGATECALL(gas, impl, 0, calldatasize, 0, 0)
        if !success: REVERT(0, 0)
        // Check frame mode via TXPARAM
        frame_idx = TXPARAM(0x10, 0)   // current frame index
        mode = TXPARAM(0x13, frame_idx) // mode of current frame
        if mode == 1 (VERIFY): APPROVE(0, 0, 3)
        else: STOP                      // SENDER frames just return
    """
    impl = bytes.fromhex(impl_addr.replace("0x", ""))
    assert len(impl) == 20

    code = bytearray()

    # If calldatasize == 0: receive ETH → STOP
    code += bytes([0x36, 0x15])        # CALLDATASIZE, ISZERO
    code += bytes([0x60, 0x00])        # PUSH1 <receive_target> (patched)
    receive_patch = len(code) - 1
    code += bytes([0x57])              # JUMPI

    # CALLDATACOPY(destOffset=0, srcOffset=0, size=calldatasize)
    code += bytes([0x36])              # CALLDATASIZE
    code += bytes([0x5f])              # PUSH0 (srcOffset)
    code += bytes([0x5f])              # PUSH0 (destOffset)
    code += bytes([0x37])              # CALLDATACOPY

    # DELEGATECALL(gas, impl, argsOffset=0, argsLen=calldatasize, retOffset=0, retLen=0)
    code += bytes([0x5f])              # PUSH0 (retLen)
    code += bytes([0x5f])              # PUSH0 (retOffset)
    code += bytes([0x36])              # CALLDATASIZE (argsLen)
    code += bytes([0x5f])              # PUSH0 (argsOffset)
    code += bytes([0x73]) + impl       # PUSH20 impl address
    code += bytes([0x5a])              # GAS
    code += bytes([0xf4])              # DELEGATECALL

    # If DELEGATECALL failed: REVERT
    code += bytes([0x15])              # ISZERO
    code += bytes([0x60, 0x00])        # PUSH1 <revert_target> (patched)
    revert_patch = len(code) - 1
    code += bytes([0x57])              # JUMPI

    # Get current frame mode via TXPARAM
    # TXPARAM(param=0x10, in2=0) → current frame index
    code += bytes([0x5f])              # PUSH0 (in2=0)
    code += bytes([0x60, 0x10])        # PUSH1 0x10 (param=current frame index)
    code += bytes([0xb0])              # TXPARAM → frame_idx on stack

    # TXPARAM(param=0x13, in2=frame_idx) → mode
    # Stack: [frame_idx]. Push param on top → [0x13, frame_idx]
    code += bytes([0x60, 0x13])        # PUSH1 0x13 (param=mode)
    code += bytes([0xb0])              # TXPARAM → mode on stack

    # If mode == 1 (VERIFY): jump to APPROVE
    code += bytes([0x60, 0x01])        # PUSH1 1
    code += bytes([0x14])              # EQ
    code += bytes([0x60, 0x00])        # PUSH1 <approve_target> (patched)
    approve_patch = len(code) - 1
    code += bytes([0x57])              # JUMPI

    # SENDER/DEFAULT mode: just STOP (return success)
    code += bytes([0x00])              # STOP

    # APPROVE target (VERIFY mode only)
    approve_target = len(code)
    code += bytes([0x5b])              # JUMPDEST
    code += bytes([0x60, 0x03])        # PUSH1 3 (scope = sender+payer)
    code += bytes([0x5f])              # PUSH0 (length)
    code += bytes([0x5f])              # PUSH0 (offset)
    code += bytes([0xaa])              # APPROVE
    code += bytes([0x00])              # STOP (unreachable, APPROVE exits)

    # REVERT target
    revert_target = len(code)
    code += bytes([0x5b])              # JUMPDEST
    code += bytes([0x5f, 0x5f, 0xfd])  # PUSH0, PUSH0, REVERT

    # RECEIVE target (accept ETH)
    receive_target = len(code)
    code += bytes([0x5b, 0x00])        # JUMPDEST, STOP

    # Patch jump targets
    code[receive_patch] = receive_target
    code[revert_patch] = revert_target
    code[approve_patch] = approve_target

    return bytes(code)


def build_creation_code(impl_addr: str,
                         verifier_addr: str, forsc_addr: str,
                         pk_seed: bytes, pk_root: bytes,
                         owner_addr: str) -> bytes:
    """Build full creation code: SSTORE storage slots + CODECOPY runtime + RETURN."""

    runtime = build_proxy_bytecode(impl_addr)

    creation = bytearray()

    # SSTORE(0, primary PQ verifier)  [slot is named spxVerifier in the
    # current JardineroFrameAccount; previous impls called it t0Verifier /
    # c11Verifier — the slot itself is agnostic.]
    v = bytes.fromhex(verifier_addr.replace("0x", "")).rjust(32, b'\x00')
    creation += bytes([0x7f]) + v      # PUSH32 verifier
    creation += bytes([0x5f, 0x55])    # PUSH0, SSTORE

    # SSTORE(1, forscVerifier)
    forsc = bytes.fromhex(forsc_addr.replace("0x", "")).rjust(32, b'\x00')
    creation += bytes([0x7f]) + forsc
    creation += bytes([0x60, 0x01, 0x55])

    # SSTORE(2, masterPkSeed)
    creation += bytes([0x7f]) + pk_seed
    creation += bytes([0x60, 0x02, 0x55])

    # SSTORE(3, masterPkRoot)
    creation += bytes([0x7f]) + pk_root
    creation += bytes([0x60, 0x03, 0x55])

    # SSTORE(4, owner)
    own = bytes.fromhex(owner_addr.replace("0x", "")).rjust(32, b'\x00')
    creation += bytes([0x7f]) + own
    creation += bytes([0x60, 0x04, 0x55])

    # CODECOPY(destOffset=0, codeOffset=len(creation)+10, size=len(runtime))
    # Then RETURN(0, len(runtime))
    codecopy_return_size = 10  # PUSH1 size, PUSH1 offset, PUSH0, CODECOPY, PUSH1 size, PUSH0, RETURN
    total_creation = len(creation) + codecopy_return_size
    creation += bytes([0x60, len(runtime)])     # PUSH1 runtime_size
    creation += bytes([0x60, total_creation])   # PUSH1 code_offset
    creation += bytes([0x5f])                   # PUSH0 (destOffset)
    creation += bytes([0x39])                   # CODECOPY
    creation += bytes([0x60, len(runtime)])     # PUSH1 runtime_size
    creation += bytes([0x5f])                   # PUSH0
    creation += bytes([0xf3])                   # RETURN
    creation += runtime

    return bytes(creation)


def main():
    parser = argparse.ArgumentParser(description="Deploy JARDÍN hand-optimized frame account")
    parser.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    parser.add_argument("--dev-key", default="0x" + DEV_KEY)
    parser.add_argument("--impl", required=True, help="Frame account Solidity impl address")
    parser.add_argument("--verifier", dest="verifier",
                        help="Primary PQ verifier address (goes in storage slot 0)")
    # Legacy aliases — all wire into `verifier`:
    parser.add_argument("--spx", dest="verifier", help=argparse.SUPPRESS)
    parser.add_argument("--c11", dest="verifier", help=argparse.SUPPRESS)
    parser.add_argument("--forsc", required=True, help="FORS+C verifier address")
    parser.add_argument("--seed", required=True, help="masterPkSeed (0x-hex)")
    parser.add_argument("--root", required=True, help="masterPkRoot (0x-hex)")
    parser.add_argument("--owner", default="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    args = parser.parse_args()

    if not args.verifier:
        parser.error("--verifier (or legacy --spx/--c11) is required")

    pk_seed = bytes.fromhex(args.seed.replace("0x", ""))
    pk_root = bytes.fromhex(args.root.replace("0x", ""))
    assert len(pk_seed) == 32 and len(pk_root) == 32

    creation = build_creation_code(
        args.impl, args.verifier, args.forsc, pk_seed, pk_root, args.owner)

    runtime = build_proxy_bytecode(args.impl)
    print(f"Proxy runtime: {len(runtime)} bytes")
    print(f"Creation code: {len(creation)} bytes")
    print(f"Runtime hex: 0x{runtime.hex()}")

    dev_key = args.dev_key.replace("0x", "")
    cast = os.path.expanduser("~/.foundry/bin/cast")
    proc = subprocess.run(
        [cast, "send", "--rpc-url", args.rpc, "--private-key", "0x" + dev_key,
         "--create", "0x" + creation.hex()],
        capture_output=True, text=True, timeout=60)

    if proc.returncode == 0:
        for line in proc.stdout.split('\n'):
            if 'contractAddress' in line:
                addr = line.split()[-1]
                print(f"\nJARDÍN Frame Proxy: {addr}")
                print(f"  impl:     {args.impl}")
                print(f"  verifier: {args.verifier}")
                print(f"  forsc:    {args.forsc}")
                break
    else:
        print(f"Failed: {proc.stderr}")


if __name__ == "__main__":
    main()
