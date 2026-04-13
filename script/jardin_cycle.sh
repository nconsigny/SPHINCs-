#!/bin/bash
# Cycle through all remaining FORS+C compact signatures (q=2..8),
# then re-register a new sub-key slot with Type 1.
set -e

export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$PATH"
source /projects/SPHINCs-/.venv/bin/activate
source /projects/SPHINCs-/.env

echo "============================================="
echo " JARDÍN Full FORS+C Cycle (q=2..8 + re-register)"
echo "============================================="
echo ""

# Send Type 2 for q=2 through q=8
for q in 2 3 4 5 6 7 8; do
    echo "--- Type 2 UserOp (q=$q) ---"
    python3 script/jardin_userop.py type2 2>&1 | grep -E "Type 2 sig|FORS\+C sig|ECDSA sig|gasUsed|transactionHash|status|Nonce|counter="
    echo ""
    sleep 6  # wait for confirmation
done

echo "============================================="
echo " FORS+C tree exhausted — re-registering new sub-key"
echo "============================================="
echo ""

# Now re-register with Type 1 (new slot)
python3 script/jardin_userop.py type1 2>&1 | grep -E "Type 1 sig|C10 sig|ECDSA sig|gasUsed|transactionHash|status|Nonce"

echo ""
echo "============================================="
echo " Cycle complete!"
echo "============================================="
