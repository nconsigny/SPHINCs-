#!/usr/bin/env python3
"""
Deploy a SPHINCS+ frame account (v2) with keys embedded in bytecode.

Keys are PUSH32 instructions in the runtime bytecode — no storage,
no SLOAD, no calldata overhead for keys. The frame account receives
sigHash(32) + raw_sig(N) and internally builds the full ABI call to
the shared verifier.

Gas savings vs v1:
  - No SLOAD (saves 4,200 gas per VERIFY frame)
  - No key calldata (saves ~1,024 gas)
  - No SSTORE at deploy (saves ~40,000 gas)
"""

import sys, os, json, subprocess, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import keccak256, to_b32, N_MASK, sign_variant, derive_keys, VARIANTS

DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def build_frame_account_bytecode(shared_verifier_addr: str, pk_seed: bytes, pk_root: bytes, variant: str = "c7") -> bytes:
    """Build v2 frame account bytecode with keys embedded in code.

    Runtime receives: sigHash(32 bytes) || raw_sig(N bytes)
    Builds in memory: verify(pkSeed, pkRoot, sigHash, sig) ABI-encoded call
    Then STATICCALLs the shared verifier and APPROVEs if true.
    """
    verifier = bytes.fromhex(shared_verifier_addr.replace("0x", ""))

    # verify(bytes32,bytes32,bytes32,bytes) selector
    verify_sel = keccak256(b"verify(bytes32,bytes32,bytes32,bytes)").to_bytes(32, "big")[:4]

    code = bytearray()

    # If calldatasize == 0: receive ETH (STOP)
    code += bytes([0x36, 0x15])  # CALLDATASIZE, ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <receive> (patched)
    receive_patch = len(code) - 1
    code += bytes([0x57])  # JUMPI

    # Build verifier calldata in memory:
    # mem[0x00:0x04] = verify selector
    code += bytes([0x63]) + verify_sel  # PUSH4 selector
    code += bytes([0x60, 0xe0, 0x1b])  # PUSH1 224, SHL (left-align in word)
    code += bytes([0x5f, 0x52])  # PUSH0, MSTORE at 0x00

    # mem[0x04:0x24] = pkSeed (embedded in bytecode as PUSH32)
    code += bytes([0x7f]) + pk_seed  # PUSH32 pkSeed
    code += bytes([0x60, 0x04, 0x52])  # PUSH1 4, MSTORE

    # mem[0x24:0x44] = pkRoot (embedded in bytecode as PUSH32)
    code += bytes([0x7f]) + pk_root  # PUSH32 pkRoot
    code += bytes([0x60, 0x24, 0x52])  # PUSH1 0x24, MSTORE

    # mem[0x44:0x64] = sigHash from calldata[0:32]
    code += bytes([0x5f, 0x35])  # PUSH0, CALLDATALOAD(0)
    code += bytes([0x60, 0x44, 0x52])  # PUSH1 0x44, MSTORE

    # mem[0x64:0x84] = 0x80 (ABI offset for bytes param = 4 words)
    code += bytes([0x60, 0x80])  # PUSH1 0x80
    code += bytes([0x60, 0x64, 0x52])  # PUSH1 0x64, MSTORE

    # mem[0x84:0xA4] = sig length = calldatasize - 32
    code += bytes([0x36])  # CALLDATASIZE
    code += bytes([0x60, 0x20, 0x90, 0x03])  # PUSH1 32, SWAP1, SUB → calldatasize-32
    code += bytes([0x60, 0x84, 0x52])  # PUSH1 0x84, MSTORE

    # mem[0xA4:...] = sig bytes from calldata[32:]
    # CALLDATACOPY(destOffset=0xA4, srcOffset=32, size=calldatasize-32)
    code += bytes([0x36])  # CALLDATASIZE
    code += bytes([0x60, 0x20, 0x90, 0x03])  # PUSH1 32, SWAP1, SUB → size
    code += bytes([0x60, 0x20])  # PUSH1 32 (srcOffset)
    code += bytes([0x60, 0xA4])  # PUSH1 0xA4 (destOffset)
    code += bytes([0x37])  # CALLDATACOPY

    # argsLen = calldatasize - 32 + 0xA4 = calldatasize + 0x84
    # STATICCALL(gas, verifier, 0, argsLen, argsLen, 32)
    code += bytes([0x36])  # CALLDATASIZE
    code += bytes([0x60, 0x84, 0x01])  # PUSH1 0x84, ADD → argsLen

    # Stack: argsLen
    # Need: gas, addr, offset(0), argsLen, retOffset(argsLen), retLen(32)
    code += bytes([0x80])  # DUP1 → [argsLen, argsLen]
    code += bytes([0x60, 0x20])  # PUSH1 32 → [32, argsLen, argsLen]
    code += bytes([0x91])  # SWAP2 → [argsLen, argsLen, 32]
    # Stack (bottom→top): 32, argsLen, argsLen
    # For STATICCALL: retLen(32), retOffset(argsLen), argsLen, offset(0), addr, gas
    code += bytes([0x5f])  # PUSH0 (argsOffset)
    code += bytes([0x73]) + verifier  # PUSH20 verifier
    code += bytes([0x5a])  # GAS
    code += bytes([0xfa])  # STATICCALL

    # Check success
    code += bytes([0x15])  # ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <revert> (patched)
    revert_patch = len(code) - 1
    code += bytes([0x57])  # JUMPI

    # Check return value: argsLen is gone from stack after STATICCALL
    # retOffset was argsLen = calldatasize + 0x84
    code += bytes([0x36, 0x60, 0x84, 0x01])  # CALLDATASIZE, PUSH1 0x84, ADD → retOffset
    code += bytes([0x51])  # MLOAD
    code += bytes([0x15])  # ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <revert> (patched)
    revert_patch2 = len(code) - 1
    code += bytes([0x57])  # JUMPI

    # APPROVE(0, 0, 3)
    code += bytes([0x60, 0x03, 0x5f, 0x5f, 0xaa, 0x00])  # PUSH1 3, PUSH0, PUSH0, APPROVE, STOP

    # REVERT
    revert_target = len(code)
    code += bytes([0x5b, 0x5f, 0x5f, 0xfd])  # JUMPDEST, PUSH0, PUSH0, REVERT

    # RECEIVE
    receive_target = len(code)
    code += bytes([0x5b, 0x00])  # JUMPDEST, STOP

    # Patch jump targets
    code[receive_patch] = receive_target
    code[revert_patch] = revert_target
    code[revert_patch2] = revert_target

    # Creation code: just CODECOPY + RETURN (no SSTORE)
    runtime = bytes(code)
    creation = bytearray()
    creation_len = 10  # PUSH1 len, PUSH1 offset, PUSH0, CODECOPY, PUSH1 len, PUSH0, RETURN
    creation += bytes([0x60, len(runtime)])  # PUSH1 runtime_len
    creation += bytes([0x60, creation_len])  # PUSH1 code_offset
    creation += bytes([0x5f, 0x39])  # PUSH0, CODECOPY
    creation += bytes([0x60, len(runtime)])  # PUSH1 runtime_len
    creation += bytes([0x5f, 0xf3])  # PUSH0, RETURN
    creation += runtime

    return bytes(creation)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    parser.add_argument("--dev-key", default="0x" + DEV_KEY)
    parser.add_argument("--shared-verifier", required=True)
    parser.add_argument("--variant", default="c7", choices=["c6", "c7"])
    args = parser.parse_args()

    rpc = args.rpc
    dev_key = args.dev_key.replace("0x", "")
    variant = args.variant

    info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f".frame_{variant}_deploy.json")

    # Generate keys
    entropy_input = bytes.fromhex(dev_key) + variant.encode()
    keygen_msg = keccak256(b"sphincs_keygen" + entropy_input)
    seed, root, _ = sign_variant(variant, keygen_msg)
    pk_seed = seed.to_bytes(32, "big")
    pk_root = root.to_bytes(32, "big")
    deploy_info = {"seed": "0x" + pk_seed.hex(), "root": "0x" + pk_root.hex(), "variant": variant}

    print(f"Variant: {variant}")
    print(f"Shared verifier: {args.shared_verifier}")
    bytecode = build_frame_account_bytecode(args.shared_verifier, pk_seed, pk_root, variant)
    print(f"Runtime: {len(bytecode) - 10} bytes, Creation: {len(bytecode)} bytes")

    proc = subprocess.run(
        ["cast", "send", "--rpc-url", rpc, "--private-key", "0x" + dev_key,
         "--create", "0x" + bytecode.hex()],
        capture_output=True, text=True, timeout=60)

    if proc.returncode == 0:
        for line in proc.stdout.split('\n'):
            if 'contractAddress' in line:
                addr = line.split()[-1]
                print(f"Frame account: {addr}")
                deploy_info.update({"frame_account": addr, "shared_verifier": args.shared_verifier, "rpc": rpc})
                with open(info_path, "w") as f:
                    json.dump(deploy_info, f, indent=2)
                break
    else:
        print(f"Failed: {proc.stderr}")


if __name__ == "__main__":
    main()
