#!/usr/bin/env python3
"""
Deploy a SPHINCS+ frame account with keys in storage (rotation-ready).

Keys are stored in EVM storage slots 0 (pkSeed) and 1 (pkRoot).
The frame account reads keys via SLOAD, builds the full ABI call to
the shared verifier, and calls APPROVE on success.

Frame data format: sigHash(32 bytes) + raw_sig(N bytes)
"""

import sys, os, json, subprocess, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import keccak256, to_b32, N_MASK, sign_variant, derive_keys, VARIANTS

DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def build_frame_account_bytecode(shared_verifier_addr: str, pk_seed: bytes, pk_root: bytes) -> bytes:
    """Build frame account bytecode with keys in storage.

    Storage layout:
      slot 0: pkSeed
      slot 1: pkRoot

    Runtime receives: sigHash(32) || raw_sig(N)
    Builds in memory: verify(pkSeed, pkRoot, sigHash, sig) ABI-encoded
    STATICCALLs shared verifier, APPROVEs if true.
    """
    verifier = bytes.fromhex(shared_verifier_addr.replace("0x", ""))
    verify_sel = keccak256(b"verify(bytes32,bytes32,bytes32,bytes)").to_bytes(32, "big")[:4]

    code = bytearray()

    # If calldatasize == 0: receive ETH
    code += bytes([0x36, 0x15])  # CALLDATASIZE, ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <receive> (patched)
    receive_patch = len(code) - 1
    code += bytes([0x57])  # JUMPI

    # mem[0x00:0x04] = verify selector
    code += bytes([0x63]) + verify_sel
    code += bytes([0x60, 0xe0, 0x1b])  # SHL 224
    code += bytes([0x5f, 0x52])  # MSTORE at 0x00

    # mem[0x04:0x24] = pkSeed from SLOAD(0)
    code += bytes([0x5f, 0x54])  # PUSH0, SLOAD(0)
    code += bytes([0x60, 0x04, 0x52])  # MSTORE at 0x04

    # mem[0x24:0x44] = pkRoot from SLOAD(1)
    code += bytes([0x60, 0x01, 0x54])  # PUSH1 1, SLOAD(1)
    code += bytes([0x60, 0x24, 0x52])  # MSTORE at 0x24

    # mem[0x44:0x64] = sigHash from calldata[0:32]
    code += bytes([0x5f, 0x35])  # PUSH0, CALLDATALOAD(0)
    code += bytes([0x60, 0x44, 0x52])  # MSTORE at 0x44

    # mem[0x64:0x84] = 0x80 (ABI offset for bytes param)
    code += bytes([0x60, 0x80])
    code += bytes([0x60, 0x64, 0x52])

    # mem[0x84:0xA4] = sig length = calldatasize - 32
    code += bytes([0x36, 0x60, 0x20, 0x90, 0x03])  # CALLDATASIZE - 32
    code += bytes([0x60, 0x84, 0x52])

    # mem[0xA4:...] = sig bytes from calldata[32:]
    code += bytes([0x36, 0x60, 0x20, 0x90, 0x03])  # size
    code += bytes([0x60, 0x20])  # srcOffset
    code += bytes([0x60, 0xA4])  # destOffset
    code += bytes([0x37])  # CALLDATACOPY

    # argsLen = calldatasize + 0x84
    code += bytes([0x36, 0x60, 0x84, 0x01])

    # STATICCALL(gas, verifier, 0, argsLen, argsLen, 32)
    code += bytes([0x80])  # DUP1
    code += bytes([0x60, 0x20])  # PUSH1 32
    code += bytes([0x91])  # SWAP2
    code += bytes([0x5f])  # PUSH0
    code += bytes([0x73]) + verifier
    code += bytes([0x5a])  # GAS
    code += bytes([0xfa])  # STATICCALL

    # Check success
    code += bytes([0x15])
    code += bytes([0x60, 0x00])
    revert_patch = len(code) - 1
    code += bytes([0x57])

    # Check return value
    code += bytes([0x36, 0x60, 0x84, 0x01])  # retOffset = calldatasize + 0x84
    code += bytes([0x51])  # MLOAD
    code += bytes([0x15])
    code += bytes([0x60, 0x00])
    revert_patch2 = len(code) - 1
    code += bytes([0x57])

    # APPROVE(0, 0, 3)
    code += bytes([0x60, 0x03, 0x5f, 0x5f, 0xaa, 0x00])

    # REVERT
    revert_target = len(code)
    code += bytes([0x5b, 0x5f, 0x5f, 0xfd])

    # RECEIVE
    receive_target = len(code)
    code += bytes([0x5b, 0x00])

    # Patch
    code[receive_patch] = receive_target
    code[revert_patch] = revert_target
    code[revert_patch2] = revert_target

    # Creation: SSTORE keys + CODECOPY runtime + RETURN
    runtime = bytes(code)
    creation = bytearray()

    # SSTORE(0, pkSeed)
    creation += bytes([0x7f]) + pk_seed
    creation += bytes([0x5f, 0x55])  # PUSH0, SSTORE

    # SSTORE(1, pkRoot)
    creation += bytes([0x7f]) + pk_root
    creation += bytes([0x60, 0x01, 0x55])  # PUSH1 1, SSTORE

    # CODECOPY + RETURN
    codecopy_len = 10
    total = len(creation) + codecopy_len
    creation += bytes([0x60, len(runtime), 0x60, total, 0x5f, 0x39])
    creation += bytes([0x60, len(runtime), 0x5f, 0xf3])
    creation += runtime

    return bytes(creation)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    parser.add_argument("--dev-key", default="0x" + DEV_KEY)
    parser.add_argument("--shared-verifier", required=True)
    parser.add_argument("--variant", default="c7", choices=["c6", "c7", "c8", "c9", "c10", "c11"])
    args = parser.parse_args()

    rpc = args.rpc
    dev_key = args.dev_key.replace("0x", "")
    variant = args.variant

    info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f".frame_{variant}_deploy.json")

    entropy_input = bytes.fromhex(dev_key) + variant.encode()
    keygen_msg = keccak256(b"sphincs_keygen" + entropy_input)
    seed, root, _ = sign_variant(variant, keygen_msg)
    pk_seed = seed.to_bytes(32, "big")
    pk_root = root.to_bytes(32, "big")

    print(f"Variant: {variant}")
    print(f"Shared verifier: {args.shared_verifier}")
    bytecode = build_frame_account_bytecode(args.shared_verifier, pk_seed, pk_root)
    print(f"Runtime: {len(bytecode) - 80} bytes, Creation: {len(bytecode)} bytes")

    proc = subprocess.run(
        ["cast", "send", "--rpc-url", rpc, "--private-key", "0x" + dev_key,
         "--create", "0x" + bytecode.hex()],
        capture_output=True, text=True, timeout=60)

    if proc.returncode == 0:
        for line in proc.stdout.split('\n'):
            if 'contractAddress' in line:
                addr = line.split()[-1]
                print(f"Frame account: {addr}")
                deploy_info = {
                    "seed": "0x" + pk_seed.hex(), "root": "0x" + pk_root.hex(),
                    "variant": variant, "frame_account": addr,
                    "shared_verifier": args.shared_verifier, "rpc": rpc
                }
                with open(info_path, "w") as f:
                    json.dump(deploy_info, f, indent=2)
                break
    else:
        print(f"Failed: {proc.stderr}")


if __name__ == "__main__":
    main()
