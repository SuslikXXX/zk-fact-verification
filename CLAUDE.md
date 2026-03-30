# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Anonymous fact verification system (diploma project). Users prove facts about themselves (e.g. age >= 18) without revealing personal data, using Zero-Knowledge proofs. The system uses a three-role model: Issuer (issues credentials), Holder (generates ZK proofs), Verifier (checks on-chain facts).

**Key design**: blockchain stores not personal data but two trust layers: IssuerRegistry (trusted issuers) and FactRegistry (verified facts). Proofs are submitted on-chain; Verifier finds facts by `verifier_id_hash + subject_tag + fact_type_hash`.

**Stack**: Go + Noir + Barretenberg + Hardhat + Solidity

## Architecture

```
Issuer --[credential]--> Holder --[proof]--> FactRegistry (on-chain)
                                                    |
Verifier <--[subject_tag + lookup]------------------+
```

### Components

- **circuits/age_over_18_v1/** — Noir ZK circuit (EdDSA + Merkle + age predicate)
- **blockchain/contracts/** — IssuerRegistry.sol, FactRegistry.sol, NoirVerifier.sol (auto-generated)
- **cli/** — Go CLI (Holder app) with subcommands: prove, submit-fact, lookup-fact
- **site/** — Demo web UI (Go backend + HTML/JS frontend)

## Cryptographic Formulas

```
subject_tag     = Poseidon(holder_secret, verifier_id_hash)
nullifier       = Poseidon(holder_secret, verifier_id_hash, fact_type_hash, idempotency_key_hash)
fact_key        = keccak256(abi.encodePacked(verifier_id_hash, subject_tag, fact_type_hash))
credential_hash = Poseidon(issuer_pubkey_x, issuer_pubkey_y, birth_date_days, schema_hash)
leaf            = Poseidon(issuer_pubkey_x, issuer_pubkey_y)
```

Poseidon variant: BN254 x5 (compatible between `go-iden3-crypto/poseidon` and `noir-lang/poseidon` v0.2.6).

## Build & Run Commands

### Prerequisites
```bash
noirup                    # Install nargo (Noir compiler)
bbup                      # Install bb (Barretenberg proving backend)
# Verify: nargo --version && bb --version
```

### Noir Circuit (from circuits/age_over_18_v1/)
```bash
nargo compile             # Compile circuit
nargo execute             # Generate witness (needs Prover.toml)
bb write_vk -b target/age_over_18_v1.json -o ./out/vk -t evm
bb prove -b target/age_over_18_v1.json -w target/age_over_18_v1.gz -o ./out/proof
bb write_solidity_verifier -k ./out/vk/vk -o ../../blockchain/contracts/NoirVerifier.sol -t evm
```

### Blockchain (from blockchain/)
```bash
npm install
npm run compile           # Compile Solidity contracts (0.8.27)
npm run node              # Start local Hardhat network (127.0.0.1:8545)
npm run deploy            # Deploy IssuerRegistry + FactRegistry + NoirVerifier
npm run test              # Run contract tests
```

### CLI (from cli/)
```bash
go build -o zk-verify ./cmd/main.go
./zk-verify import-credential --file testdata/credential.json
./zk-verify prove                    # Needs .env with HOLDER_SECRET, etc.
./zk-verify submit-fact --proof proof_package.json
./zk-verify lookup-fact --verifier-id-hash 0x... --subject-tag 0x... --fact-type-hash 0x...
./zk-verify verify-service-flow      # E2E: prove -> submit -> lookup
```

CLI config via .env: CREDENTIALS_FILE, REQUEST_FILE, POLICY_FILE, HOLDER_SECRET, NOIR_CIRCUIT_DIR, FACT_REGISTRY_ADDRESS, ETHEREUM_RPC_URL, HOLDER_PRIVATE_KEY, CHAIN_ID.

### Site (from site/)
```bash
cd backend && go run main.go         # Starts on :8080
```

## Noir Circuit Structure (age_over_18_v1)

**Private inputs**: birth_date_days, holder_secret, issuer_pubkey_x/y, sig_r8x/r8y/s, merkle_path[16], merkle_index_bits[16], idempotency_key_hash

**Public inputs**: verifier_id_hash, fact_type_hash, issuer_policy_root, schema_hash, subject_tag, nullifier, valid_until, cutoff_date_days

**Checks**: (1) birth_date_days <= cutoff_date_days, (2) EdDSA signature valid, (3) issuer in Merkle tree (depth 16, Poseidon), (4) subject_tag matches, (5) nullifier matches

**Dependencies**: `poseidon` v0.2.6 (noir-lang/poseidon), `eddsa` v0.1.3 (noir-lang/eddsa)

## Smart Contracts (Solidity 0.8.27)

- **NoirVerifier.sol** — Auto-generated from bb. `verify(bytes proof, bytes32[] publicInputs) -> bool`. Do NOT edit manually.
- **IssuerRegistry.sol** — Trusted issuer registry. `addIssuer()`, `deactivateIssuer()`, `isActive()`.
- **FactRegistry.sol** — Stores VerifiedFact records. `submitVerifiedFact()` verifies proof + checks nullifier + stores fact. `getFact()` and `isFactValid()` for lookups by fact_key.

## CLI Package Layout (cli/internal/)

| Package | Purpose |
|---------|---------|
| config | Loads .env configuration |
| creds | Credential model (spec 7.2), loading |
| request | VerificationRequest model (spec 7.1), loading, validation |
| policy | IssuerPolicy model (spec 7.3), Poseidon Merkle tree (depth 16) |
| prover | ProverInput/ProofPackage models, subject_tag/nullifier computation, nargo/bb invocation |
| blockchain | SubmitFact (sends tx), LookupFact (reads VerifiedFact), ABI encoding |
| result | VerificationResult model (spec 7.7) |
| functions | HexToFieldElement utility |

## JSON Data Formats (per specification)

7 JSON objects flow through the system: verification_request.json (Verifier->Holder), credential.json (Issuer->Holder, local only), issuer_policy.json, prover_input.json (internal), proof_package.json (Holder output), onchain_submit.json, verification_result.json (Verifier log).

## Known Limitations / TODOs

- EdDSA signatures in testdata are zeroed (placeholder) — need real key generation via go-iden3-crypto/babyjub
- Merkle tree in testdata has placeholder root — need to compute real root from issuer leaves
- Site backend fact lookup is a stub (needs ethclient integration)
- NoirVerifier.sol exceeds 24KB contract size limit for mainnet (OK for dev/testnet)
- No revocation check in circuit yet
