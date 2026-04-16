#!/bin/bash
# Generate JARDÍN signature and verify on-chain via cast call
set -e

export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$PATH"
source /projects/SPHINCs-/.venv/bin/activate
source /projects/SPHINCs-/.env

VERIFIER="0x624A925D482DeacA51488aac0732a810810F778f"
MESSAGE="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

echo "=== Generating JARDÍN signature (q=1, balanced h=7) ===" >&2

# Get ABI-encoded output from signer
ABI_HEX=$(python3 script/jardin_signer.py "$MESSAGE" 1)

# Parse: first 32 bytes = pkSeed, next 32 = pkRoot, rest = sig (after offset+length)
PKSEED="0x${ABI_HEX:2:64}"
PKROOT="0x${ABI_HEX:66:64}"
# Offset is at bytes 64..96 (= 0x60 = 96), length at 96..128
SIG_LEN_HEX="${ABI_HEX:194:64}"
SIG_LEN=$((16#${SIG_LEN_HEX}))
# Sig data starts at byte 128 (hex offset 258)
SIG_HEX="${ABI_HEX:258:$((SIG_LEN * 2))}"

echo "  pkSeed: $PKSEED" >&2
echo "  pkRoot: $PKROOT" >&2
echo "  sig length: $SIG_LEN bytes" >&2

echo "=== Calling verifier on Sepolia ===" >&2
cast call "$VERIFIER" \
  "verifyForsC(bytes32,bytes32,bytes32,bytes)(bool)" \
  "$PKSEED" "$PKROOT" "$MESSAGE" "0x${SIG_HEX}" \
  --rpc-url "$SEPOLIA_RPC_URL" 2>&1

echo ""
echo "=== Done ===" >&2
