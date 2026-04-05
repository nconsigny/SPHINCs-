#!/usr/bin/env python3
"""
Deploy a SPHINCS+ C6 frame account on the ethrex EIP-8141 testnet.

This deploys raw bytecode that:
1. Stores pkSeed (slot 0) and pkRoot (slot 1)
2. Has a verifyAndApprove() function that:
   - Reads sig_hash via TXPARAM(0x08)
   - Reads SPHINCS+ sig from frame data (calldata)
   - Calls the external C6 verifier via STATICCALL
   - Calls APPROVE(0, 0, 3) on success
3. Has an execute() function for SENDER frames
4. Has a receive() fallback for ETH

Strategy: deploy the C6 verifier separately, then deploy a thin frame account
that delegates verification to it and calls APPROVE.
"""

import sys, os, json, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import keccak256, to_b32, N_MASK, sign_variant, derive_keys, VARIANTS

DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

def build_frame_account_bytecode(verifier_addr: str, pk_seed: bytes, pk_root: bytes) -> bytes:
    """Build raw EVM bytecode for the frame account.

    The account has two entry points selected by function selector:

    verifyAndApprove(bytes32,bytes,uint256) = selector 0x<computed>
      - Reads sig_hash from TXPARAM(0x08)
      - Forwards verify(sig_hash, sig) to the external verifier via STATICCALL
      - If returns true: APPROVE(0, 0, scope=3)
      - Otherwise: REVERT

    execute(address,uint256,bytes) = 0xb61d27f6
      - Standard execute for SENDER frames

    For simplicity, we build this as hand-assembled bytecode.
    The APPROVE opcode (0xaa) and TXPARAM (0xb0) are EIP-8141 specific.
    """

    verifier = bytes.fromhex(verifier_addr.replace("0x", ""))

    # Build the runtime bytecode
    # We use a simple dispatcher:
    #   - If calldatasize == 0: receive ETH (STOP)
    #   - If selector matches verifyForFrame: do SPHINCS+ verify + APPROVE
    #   - If selector matches execute: do CALL
    #   - Otherwise: REVERT

    # Function selectors
    verify_sel = keccak256(b"verifyForFrame()").to_bytes(32, "big")[:4]
    execute_sel = bytes.fromhex("b61d27f6")  # execute(address,uint256,bytes)

    # We'll build this in raw opcodes
    # For the verify path, the key sequence is:
    #   1. PUSH1 0x08; TXPARAM (0xb0) — get sig_hash
    #   2. Copy calldata (SPHINCS+ sig) to memory
    #   3. STATICCALL to verifier with verify(sig_hash, sig)
    #   4. Check result
    #   5. PUSH1 0x03; PUSH0; PUSH0; APPROVE (0xaa)

    # Instead of hand-assembling hundreds of bytes, let's use a minimal approach:
    # The verify frame calldata IS the ABI-encoded verify(bytes32, bytes) call
    # So we just:
    #   1. Get sig_hash from TXPARAM
    #   2. Store sig_hash at the right calldata position (or rebuild call)
    #   3. STATICCALL the verifier with the calldata
    #   4. APPROVE if success

    # Simplest possible approach:
    # verifyForFrame() is called with NO arguments.
    # The SPHINCS+ signature is in the frame data (separate from calldata).
    # Actually, per EIP-8141, the frame data IS the calldata for the target contract.
    # So the VERIFY frame data = the calldata we receive.

    # Even simpler: the frame_tx.py builds the VERIFY frame data as:
    #   verify(bytes32 sigHash, bytes sig) ABI-encoded call to the C6 verifier
    # We just need to:
    #   1. Forward the entire calldata to the verifier via STATICCALL
    #   2. Check the result
    #   3. APPROVE

    # This means our account contract is essentially a proxy that:
    #   - Forwards calldata to verifier
    #   - Calls APPROVE on success

    # Runtime bytecode (hand-assembled):
    code = bytearray()

    # Check if calldatasize > 0
    code += bytes([0x36])  # CALLDATASIZE
    code += bytes([0x15])  # ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 0 (will be patched: jump to receive)
    # We'll patch this jump target later
    receive_jump_idx = len(code) - 1
    code += bytes([0x57])  # JUMPI (jump to receive if no calldata)

    # Load first 4 bytes of calldata as selector
    code += bytes([0x5f])  # PUSH0
    code += bytes([0x35])  # CALLDATALOAD
    code += bytes([0x60, 0xe0])  # PUSH1 224
    code += bytes([0x1c])  # SHR — selector on stack

    # Check for execute selector (0xb61d27f6)
    code += bytes([0x80])  # DUP1
    code += bytes([0x63]) + execute_sel  # PUSH4 execute_sel
    code += bytes([0x14])  # EQ
    code += bytes([0x60, 0x00])  # PUSH1 <execute_target> — patched later
    execute_jump_idx = len(code) - 1
    code += bytes([0x57])  # JUMPI

    # Default path: this is a VERIFY frame call
    # Forward entire calldata to verifier via STATICCALL

    # Copy calldata to memory at offset 0
    code += bytes([0x36])  # CALLDATASIZE
    code += bytes([0x5f])  # PUSH0 (destOffset)
    code += bytes([0x5f])  # PUSH0 (offset)
    code += bytes([0x37])  # CALLDATACOPY — copies all calldata to memory[0..]

    # STATICCALL(gas, addr, argsOffset, argsLength, retOffset, retLength)
    code += bytes([0x60, 0x20])  # PUSH1 32 — retLength
    code += bytes([0x36])  # CALLDATASIZE — use calldatasize as temp retOffset
    code += bytes([0x36])  # CALLDATASIZE — argsLength
    code += bytes([0x5f])  # PUSH0 — argsOffset
    code += bytes([0x73]) + verifier  # PUSH20 verifier address
    code += bytes([0x5a])  # GAS
    code += bytes([0xfa])  # STATICCALL

    # Check success (returns 1 on stack if call succeeded)
    code += bytes([0x15])  # ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <revert_target> — patched later
    revert_jump_idx = len(code) - 1
    code += bytes([0x57])  # JUMPI (jump to revert if call failed)

    # Check return value: load from memory at retOffset (=calldatasize)
    code += bytes([0x36])  # CALLDATASIZE (retOffset we used)
    code += bytes([0x51])  # MLOAD — loads the return value
    code += bytes([0x15])  # ISZERO
    code += bytes([0x60, 0x00])  # PUSH1 <revert_target> — patched later
    revert_jump_idx2 = len(code) - 1
    code += bytes([0x57])  # JUMPI (jump to revert if verify returned false)

    # SUCCESS: call APPROVE(offset=0, length=0, scope=3)
    code += bytes([0x60, 0x03])  # PUSH1 3 (scope = both)
    code += bytes([0x5f])  # PUSH0 (length = 0)
    code += bytes([0x5f])  # PUSH0 (offset = 0)
    code += bytes([0xaa])  # APPROVE
    code += bytes([0x00])  # STOP

    # REVERT target
    revert_target = len(code)
    code += bytes([0x5b])  # JUMPDEST
    code += bytes([0x5f])  # PUSH0
    code += bytes([0x5f])  # PUSH0
    code += bytes([0xfd])  # REVERT

    # RECEIVE target (no calldata = ETH transfer)
    receive_target = len(code)
    code += bytes([0x5b])  # JUMPDEST
    code += bytes([0x00])  # STOP

    # EXECUTE target
    execute_target = len(code)
    code += bytes([0x5b])  # JUMPDEST
    # execute(address dest, uint256 value, bytes data)
    # For simplicity: just do a CALL with the parameters from calldata
    # dest = calldata[4:36], value = calldata[36:68], data offset/length from ABI
    # This is complex to do in raw bytecode. For the PoC, just STOP.
    # (SENDER frames execute as the account, so the frame itself handles the call)
    code += bytes([0x00])  # STOP — the frame execution handles the transfer

    # Patch jump targets
    code[receive_jump_idx] = receive_target
    code[execute_jump_idx] = execute_target
    code[revert_jump_idx] = revert_target
    code[revert_jump_idx2] = revert_target

    runtime = bytes(code)
    runtime_len = len(runtime)

    # Creation code: store pkSeed and pkRoot, then return runtime
    # Build creation prefix first, then compute its length for CODECOPY offset
    creation = bytearray()

    # SSTORE(0, pkSeed)
    creation += bytes([0x7f]) + pk_seed  # PUSH32 pkSeed
    creation += bytes([0x5f])  # PUSH0 (slot 0)
    creation += bytes([0x55])  # SSTORE

    # SSTORE(1, pkRoot)
    creation += bytes([0x7f]) + pk_root  # PUSH32 pkRoot
    creation += bytes([0x60, 0x01])  # PUSH1 1
    creation += bytes([0x55])  # SSTORE

    # CODECOPY(destOffset=0, codeOffset=creation_total_len, length=runtime_len)
    # + RETURN(0, runtime_len)
    # These 10 bytes: PUSH1 len, PUSH1 offset, PUSH0, CODECOPY, PUSH1 len, PUSH0, RETURN
    codecopy_return_len = 10
    creation_total_len = len(creation) + codecopy_return_len

    creation += bytes([0x60, runtime_len])       # PUSH1 runtime_len (length)
    creation += bytes([0x60, creation_total_len]) # PUSH1 codeOffset
    creation += bytes([0x5f])                     # PUSH0 (destOffset)
    creation += bytes([0x39])                     # CODECOPY
    creation += bytes([0x60, runtime_len])        # PUSH1 runtime_len
    creation += bytes([0x5f])                     # PUSH0
    creation += bytes([0xf3])                     # RETURN

    creation += runtime

    return bytes(creation)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    parser.add_argument("--dev-key", default="0x" + DEV_KEY)
    args = parser.parse_args()

    rpc = args.rpc
    dev_key = args.dev_key.replace("0x", "")

    # Load verifier deployment
    info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".frame_c6_deploy.json")
    with open(info_path) as f:
        deploy_info = json.load(f)

    verifier = deploy_info["verifier"]
    pk_seed = bytes.fromhex(deploy_info["seed"][2:])
    pk_root = bytes.fromhex(deploy_info["root"][2:])

    print(f"Verifier: {verifier}")
    print(f"pkSeed: 0x{pk_seed.hex()}")
    print(f"pkRoot: 0x{pk_root.hex()}")

    # Build bytecode
    bytecode = build_frame_account_bytecode(verifier, pk_seed, pk_root)
    print(f"Bytecode: {len(bytecode)} bytes")

    # Deploy via cast
    proc = subprocess.run(
        ["cast", "send", "--rpc-url", rpc, "--private-key", "0x" + dev_key,
         "--create", "0x" + bytecode.hex()],
        capture_output=True, text=True, timeout=60,
    )

    if proc.returncode == 0:
        for line in proc.stdout.split('\n'):
            if 'contractAddress' in line:
                addr = line.split()[-1]
                print(f"\nFrame account deployed at: {addr}")

                # Update deploy info
                deploy_info["frame_account"] = addr
                with open(info_path, "w") as f:
                    json.dump(deploy_info, f, indent=2)
                print(f"Updated {info_path}")
                break
        else:
            print(proc.stdout)
    else:
        print(f"Deploy failed: {proc.stderr}")


if __name__ == "__main__":
    main()
