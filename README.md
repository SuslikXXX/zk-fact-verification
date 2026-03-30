# Anonymous Fact Verification System

Zero-Knowledge proof system for anonymous verification of user facts (age 18+, diploma, KYC, etc.) without revealing personal data.

Built on: **Go + Noir + Barretenberg + Hardhat + Solidity**

## Architecture

```
Issuer ──[credential]──> Holder ──[ZK proof]──> FactRegistry (on-chain)
                                                       │
Verifier <──[subject_tag + on-chain lookup]────────────┘
```

- **Issuer** — verifies real documents, issues signed credential (EdDSA BabyJubJub)
- **Holder** — stores credential locally, builds ZK proof, publishes verified fact to blockchain
- **Verifier** — receives `subject_tag`, looks up on-chain fact, grants service
- **Blockchain** — stores `IssuerRegistry` (trusted issuers) and `FactRegistry` (verified facts), never personal data

## Prerequisites

```bash
# Noir compiler
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.zshrc
noirup

# Barretenberg proving backend
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
source ~/.zshrc
bbup

# Go 1.24+
# Node.js 18+ & npm

# Verify
nargo --version   # 1.0.0-beta.19
bb --version      # 4.0.0-nightly.20260120
```

## Quick Start (E2E Test)

### 1. Generate test data (EdDSA keys, Merkle tree, credential)

```bash
cd cli
go mod tidy
cd testdata
go run generate.go
cd ../..
```

### 2. Compile Noir circuit and generate proof

```bash
cd circuits/age_over_18_v1

# Compile circuit
nargo compile

# Generate witness from Prover.toml (created by generate.go)
nargo execute

# Write verification key (EVM target)
bb write_vk -b ./target/age_over_18_v1.json -o ./target_evm -t evm

# Generate ZK proof (EVM target)
bb prove -b ./target/age_over_18_v1.json -w ./target/age_over_18_v1.gz \
  -o ./target_evm/proof -k ./target_evm/vk -t evm

# Verify proof locally (optional)
bb write_vk -b ./target/age_over_18_v1.json -o ./target
cp ./target/proof/public_inputs ./target/public_inputs 2>/dev/null
bb prove -b ./target/age_over_18_v1.json -w ./target/age_over_18_v1.gz -o ./target/proof
bb verify -k ./target/vk -p ./target/proof/proof

cd ../..
```

### 3. Deploy smart contracts

```bash
cd blockchain
npm install

# Start local Ethereum node (keep running in separate terminal)
npm run node

# In another terminal — deploy contracts
npm run deploy

cd ..
```

### 4. Run on-chain E2E test

```bash
cd blockchain
npx hardhat run scripts/test-e2e.ts --network localhost
```

Expected output:
```
Proof valid: true
TX status: SUCCESS
Fact exists: true
Correctly reverted: YES - Nullifier already used
```

## CLI Usage

```bash
cd cli
go build -o zk-verify ./cmd/main.go

# Import and validate credential
./zk-verify import-credential --file testdata/credential.json

# Generate ZK proof (requires .env with HOLDER_SECRET, etc.)
./zk-verify prove

# Submit proof to FactRegistry
./zk-verify submit-fact --proof proof_package.json

# Look up verified fact on-chain
./zk-verify lookup-fact \
  --verifier-id-hash 0x... \
  --subject-tag 0x... \
  --fact-type-hash 0x...

# Full E2E flow
./zk-verify verify-service-flow
```

### CLI Environment (.env)

```env
CREDENTIALS_FILE=testdata/credential.json
REQUEST_FILE=testdata/verification_request.json
POLICY_FILE=testdata/issuer_policy.json
HOLDER_SECRET=0x00deadbeef...
NOIR_CIRCUIT_DIR=../circuits/age_over_18_v1
FACT_REGISTRY_ADDRESS=0x...    # from deployment.json
ETHEREUM_RPC_URL=http://127.0.0.1:8545
HOLDER_PRIVATE_KEY=0xac0974...  # Hardhat account #0
CHAIN_ID=31337
```

## Project Structure

```
blockchain_diplom/
├── circuits/age_over_18_v1/   # Noir ZK circuit
│   ├── Nargo.toml             # Dependencies: poseidon v0.2.6, eddsa v0.1.3
│   └── src/main.nr            # EdDSA + Merkle + age predicate + subject_tag + nullifier
├── blockchain/                # Hardhat + Solidity
│   ├── contracts/
│   │   ├── NoirVerifier.sol   # Auto-generated from bb (DO NOT EDIT)
│   │   ├── IssuerRegistry.sol # Trusted issuer registry
│   │   └── FactRegistry.sol   # Verified fact storage + proof verification
│   └── scripts/
│       ├── deploy.ts          # Deploy all contracts
│       └── test-e2e.ts        # On-chain E2E test
├── cli/                       # Go CLI (Holder app)
│   ├── cmd/main.go            # Subcommands: prove, submit-fact, lookup-fact
│   ├── internal/              # config, creds, request, policy, prover, blockchain, result
│   └── testdata/
│       ├── generate.go        # Generate real EdDSA keys + test data
│       ├── credential.json
│       ├── verification_request.json
│       └── issuer_policy.json
└── site/                      # Demo web UI
    ├── backend/main.go        # Go HTTP server
    └── frontend/index.html    # Verifier lookup panel
```

## Cryptographic Design

| Formula | Computation |
|---------|------------|
| `subject_tag` | `Poseidon(holder_secret, verifier_id_hash)` |
| `nullifier` | `Poseidon(holder_secret, verifier_id_hash, fact_type_hash, idempotency_key_hash)` |
| `fact_key` | `keccak256(verifier_id_hash, subject_tag, fact_type_hash)` |
| `credential_hash` | `Poseidon(issuer_pubkey_x, issuer_pubkey_y, birth_date_days, schema_hash)` |
| `leaf` | `Poseidon(issuer_pubkey_x, issuer_pubkey_y)` |

- Poseidon: BN254 x5 variant (`go-iden3-crypto` = `noir-lang/poseidon` v0.2.6)
- EdDSA: BabyJubJub curve over BN254 (`go-iden3-crypto/babyjub` = `noir-lang/eddsa` v0.1.3)
- Merkle tree: depth 16, Poseidon hash, max 65536 issuers

## Smart Contracts

| Contract | Purpose |
|----------|---------|
| `NoirVerifier` (HonkVerifier) | Auto-generated Solidity verifier from Barretenberg. `verify(proof, publicInputs)` |
| `IssuerRegistry` | Trusted issuer registry. `addIssuer()`, `deactivateIssuer()`, `isActive()` |
| `FactRegistry` | Stores `VerifiedFact` records. `submitVerifiedFact()` — verifies proof + checks nullifier + stores fact. `getFact()` / `isFactValid()` for lookups |

## ZK Circuit (age_over_18_v1)

**Proves without revealing personal data:**
1. `birth_date_days <= cutoff_date_days` (age >= 18)
2. EdDSA signature valid (credential authenticity)
3. Issuer in Merkle tree (trusted issuer set)
4. `subject_tag` correctly derived (verifier-scoped pseudonym)
5. `nullifier` correctly derived (replay protection)

## License

MIT
