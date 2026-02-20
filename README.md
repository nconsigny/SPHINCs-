# SPHINCs- — Post-Quantum ERC-4337 Smart Account

---

> ## WARNING: RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE
>
> This codebase is a scheme exploration for lightweight variants of SPHINCS+.
> It has **not been audited**, contains **no security guarantees**, and is
> **not safe to use with real funds**. Cryptographic parameters, key derivation,
> and contract logic have not been reviewed by any third party.
> **Use on testnets only.**

---

A hybrid **ECDSA + SPHINCS+** ERC-4337 smart account for Ethereum, implementing post-quantum signature verification on-chain using hand-optimised Yul/assembly verifiers.

## Architecture

```
EOA (ECDSA key)
    │
    ├── signs UserOp (classical, secp256k1)
    │
    └── derives SPHINCS+ keypair (off-chain, Python)
            │
            ├── pkSeed + pkRoot → stored in SphincsWc*Asm verifier (on-chain)
            └── sk_seed         → never stored, rederived per signing session

UserOp signature = abi.encode(ecdsaSig[65], sphincsSig[3596–4264])

EntryPoint.handleOps()
    └── SphincsAccount._validateSignature()
            ├── ECDSA.recover(userOpHash, ecdsaSig) == owner
            └── verifier.staticcall(verify(userOpHash, sphincsSig)) == true
```

Both signatures must be valid. Compromising ECDSA alone is not enough — a quantum attacker would also need to forge SPHINCS+.

## Variants

| Variant | Scheme | Sig size | ASM verify gas | Security |
|---|---|---|---|---|
| C2 | FORS+C h=18 d=2 | 4264 bytes | ~190K | 128-bit |
| C3 | PORS+FP h=27 d=3 | 3596 bytes | ~260K | 128-bit |

Full ERC-4337 transaction cost (including calldata, EntryPoint overhead, ECDSA, execute): ~412K (C2) / ~444K (C3).

## Key Derivation

SPHINCS+ keys are derived **entirely off-chain** from the ECDSA private key. The contract only stores the public key (`pkSeed`, `pkRoot`) — it never sees any private key material.

```
ECDSA private key
    │
    ▼  keccak256("sphincs_keygen" || ecdsa_key || variant)
keygen_message
    │
    ▼  keccak256("sphincs_signer_v1" || keygen_message)
entropy
    ├──▶ keccak256("pk_seed" || entropy) → pkSeed  (public, on-chain)
    └──▶ keccak256("sk_seed" || entropy) → sk_seed (secret, never stored)
                                                │
                                                ▼
                                          hypertree build → pkRoot (public, on-chain)
```

### Comparison with BIP32 HD wallets

| Property | BIP32 HD wallet | This scheme |
|---|---|---|
| Master secret | BIP39 mnemonic → 512-bit seed | ECDSA private key (32 bytes) |
| Derivation | HMAC-SHA512, hardened paths | keccak256 chain with domain tags |
| Key separation | Cryptographic path isolation | Domain-separated prefixes |
| Standard | BIP32/BIP44 | Ad-hoc |
| Parent compromise | Exposes non-hardened children only | Exposes SPHINCS+ key |

**Limitation:** if the ECDSA private key is compromised, the SPHINCS+ key is also compromised since it is derived from it. For production use, the SPHINCS+ secret should be derived directly from a BIP32 master seed at a dedicated hardened path (e.g. `m/purpose'/variant'`), keeping it independent from the ECDSA signing key.

## Deployed Contracts (Sepolia)

| Contract | Address |
|---|---|
| SphincsAccountFactory | `0xcde095f18801e6623Fb9fb7246d6b08f24aDbbC6` |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

## Setup

```bash
# Install Foundry dependencies
forge build

# Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install eth-account eth-abi requests pycryptodome
```

## Environment

Create `.env` in the project root:

```bash
PRIVATE_KEY=0x<funded_sepolia_eoa_private_key>
PIMLICO_API_KEY=<pimlico_api_key>          # optional, not required for direct handleOps
SEPOLIA_RPC_URL=https://rpc.ankr.com/eth_sepolia/<key>
```

## Deploy

```bash
forge script script/DeploySepolia.s.sol --rpc-url sepolia --broadcast
```

## Create Account

```bash
# Generates SPHINCS+ keypair (~10s), prints counterfactual address + cast send command
python3 script/send_userop.py create \
  --factory <factory_address> \
  --ecdsa-key $PRIVATE_KEY \
  --variant c2   # or c3
```

Then run the printed `cast send` command to deploy the account on-chain, and fund it with Sepolia ETH.

## Send UserOp

```bash
python3 script/send_userop.py send \
  --account <account_address> \
  --ecdsa-key $PRIVATE_KEY \
  --to <recipient> \
  --value 0.001 \
  --variant c2   # or c3
```

## Tests

```bash
forge test                          # all 23 tests
forge test --match-contract AsmBenchmark -vv   # gas benchmarks
```
