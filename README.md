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

A research repo for **post-quantum ERC-4337 accounts**, currently containing:

- the original hybrid **ECDSA + SPHINCS+** smart account path
- a standalone **WOTS+C one-time account**
- a **persistent WOTS+C Merkle-tree account** with `h=9` (`512` leaves per root)

All schemes in this branch are testnet-only research artifacts.

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
| C2 | FORS+C h=18 d=2 | 4264 bytes | ~190K | 128-bit post-quantum |
| C3 | PORS+FP h=27 d=3 | 3596 bytes | ~260K | 128-bit post-quantum |

Full ERC-4337 transaction cost (including calldata, EntryPoint overhead, ECDSA, execute): ~412K (C2) / ~444K (C3).

## WOTS+C Accounts

This branch also adds two Keccak-based WOTS+C ERC-4337 account variants.

| Account | Signature bytes | Local `validateUserOp` | Capacity |
|---|---:|---:|---:|
| `WotsOtsAccount` | `516` | `~54.8k` | `1` signature |
| `PersistentWotsAccount` (`h=9`) | `660` | `~74.1k` | `512` signatures per root |

The persistent account binds the EntryPoint nonce to the Merkle leaf index. Each UserOperation carries:

- one WOTS+C signature for leaf `i`
- a 9-node Merkle authentication path
- no separate on-chain "used bit"

`h=9` means one root authorises `2^9 = 512` transactions. Root rotation is the next step and is not implemented in this branch yet.

## Measured Persistent WOTS+C Sepolia Send

Measured from the successful Sepolia token send:

- tx hash: `0xfb888b5a41c6086aad472e35dde027edd61ef438fce587058deb4f03f160dc9f`
- wallet: `0x54829040FF4D94e53d11279380f8de8c3EBCE7ba`
- token: `USDC (test)` `0xbe72E441BF55620febc26715db68d3494213D8Cb`
- recipient: `0x50EBa181bd0770bD145dC543617e457666B017fD`

Gas split:

| Bucket | Gas |
|---|---:|
| ERC-20 `transfer(...)` subcall | `29,764` |
| Wallet-specific WOTS+C auth | `82,635` |
| Shared ERC-4337 / AA overhead | `106,444` |
| Total tx gas | `218,843` |

The measured premium in this branch is mostly in the hash-based authorization path, not in the shared ERC-4337 envelope.

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
| WotsOtsAccountFactory | `0x9EFf47782da77C096D1e3B2C5D37517655F3664f` |
| PersistentWotsAccountFactory (`h=9`) | `0xDD84b92Caba7abced7CA5d0553696aAFA89cF1CD` |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

Example branch artifacts on Sepolia:

- one-time WOTS account: `0xfd030C31d9A828BC2C48B08AEC05C57E3cF80be6`
- persistent `h=9` WOTS account: `0x54829040FF4D94e53d11279380f8de8c3EBCE7ba`
- persistent factory deploy tx: `0xeaad871cd76bb89657c4ce0876f537bc73c543a87ef7cd27c24b2f636c899ff1`
- persistent account create tx: `0x169ac9c99fc13d213af08f1d5296813c423c6f21a12a7785f74d5d24568608dd`
- persistent wallet ETH funding tx: `0xb974a32f9c1a6046f00820177d09e241729070c1e444b3a3e6780a2dd820efba`
- persistent wallet test-USDC funding tx: `0x5b575b81a01a4cd396be277349479d11ca04abe959e34107da4d69ce6f31bd6d`
- persistent wallet successful 2-USDC send: `0xfb888b5a41c6086aad472e35dde027edd61ef438fce587058deb4f03f160dc9f`

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
# SPHINCS+ hybrid factory
forge script script/DeploySepolia.s.sol --rpc-url sepolia --broadcast

# WOTS+C one-time factory
forge script script/DeployWotsSepolia.s.sol --rpc-url sepolia --broadcast

# WOTS+C persistent h=9 factory
forge script script/DeployPersistentWotsH9Sepolia.s.sol --rpc-url sepolia --broadcast
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

WOTS+C helpers:

```bash
# One-time WOTS+C keygen
python3 script/wots_ots_signer.py keygen <entropy_hex>

# Persistent h=9 WOTS+C keygen
python3 script/persistent_wots_h9_signer.py keygen <entropy_hex>
```

The WOTS factories are plain CREATE2 factories. Use the emitted `pkSeed` + `pkHash` or `pkRoot` with `createAccount(...)`.

## Send UserOp

```bash
python3 script/send_userop.py send \
  --account <account_address> \
  --ecdsa-key $PRIVATE_KEY \
  --to <recipient> \
  --value 0.001 \
  --variant c2   # or c3
```

The branch also contains a Sepolia demo sender for the persistent `h=9` WOTS account:

```bash
export PERSISTENT_WOTS_ACCOUNT=<persistent_account_address>
export PERSISTENT_WOTS_ENTROPY=<32_byte_entropy_hex>
forge script script/SendPersistentWotsUsdcSepolia.s.sol --rpc-url "$SEPOLIA_RPC_URL" --broadcast
```

This script is intentionally branch-specific. It submits a direct `EntryPoint.handleOps(...)` call for the demo `USDC (test)` transfer used in the Sepolia run above.

## Tests

```bash
forge test
forge test --match-contract WotsOtsE2E -vv
forge test --match-contract PersistentWotsH9E2E -vv
forge test --match-contract AsmBenchmark -vv
```
