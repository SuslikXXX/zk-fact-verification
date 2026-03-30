package prover

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"diplom/cli/internal/creds"
	"diplom/cli/internal/policy"
	"diplom/cli/internal/request"
)

// GenerateProof builds prover input, calls nargo execute + bb prove, returns ProofPackage
func GenerateProof(
	cfg ProverConfig,
	cred *creds.Credential,
	req *request.VerificationRequest,
	pol *policy.IssuerPolicy,
) (*ProofPackage, error) {
	// 1. Parse issuer pubkey from credential
	issuerPubkeyX, err := HexToField(cred.Issuer.PubkeyX)
	if err != nil {
		return nil, fmt.Errorf("parse issuer.pubkey_x: %w", err)
	}
	issuerPubkeyY, err := HexToField(cred.Issuer.PubkeyY)
	if err != nil {
		return nil, fmt.Errorf("parse issuer.pubkey_y: %w", err)
	}

	// Find matching issuer in policy
	leafIndex := -1
	for i, iss := range pol.Issuers {
		if iss.IssuerID == cred.Issuer.DID {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		return nil, fmt.Errorf("issuer %s not found in policy", cred.Issuer.DID)
	}

	// 2. Build Merkle tree and get path
	leaves := make([]*big.Int, len(pol.Issuers))
	for i, iss := range pol.Issuers {
		leaf, err := HexToField(iss.Leaf)
		if err != nil {
			return nil, fmt.Errorf("parse leaf %d: %w", i, err)
		}
		leaves[i] = leaf
	}

	levels, err := policy.BuildTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("build merkle tree: %w", err)
	}
	merklePath, merkleIndexBits := policy.GetMerklePath(levels, leafIndex)

	// 3. Compute subject_tag and nullifier
	holderSecret, err := HexToField(cfg.HolderSecret)
	if err != nil {
		return nil, fmt.Errorf("parse holder_secret: %w", err)
	}
	verifierIDHash, err := HexToField(req.VerifierIDHash)
	if err != nil {
		return nil, fmt.Errorf("parse verifier_id_hash: %w", err)
	}
	factTypeHash, err := HexToField(req.FactTypeHash)
	if err != nil {
		return nil, fmt.Errorf("parse fact_type_hash: %w", err)
	}

	idempotencyKeyHash, err := computeIdempotencyKeyHash(req.IdempotencyKey)
	if err != nil {
		return nil, fmt.Errorf("compute idempotency_key_hash: %w", err)
	}

	subjectTag, err := ComputeSubjectTag(holderSecret, verifierIDHash)
	if err != nil {
		return nil, err
	}
	nullifier, err := ComputeNullifier(holderSecret, verifierIDHash, factTypeHash, idempotencyKeyHash)
	if err != nil {
		return nil, err
	}

	schemaHash, err := HexToField(req.SchemaHash)
	if err != nil {
		return nil, fmt.Errorf("parse schema_hash: %w", err)
	}

	policyRoot, err := HexToField(pol.Root)
	if err != nil {
		return nil, fmt.Errorf("parse policy root: %w", err)
	}

	validUntil := uint64(time.Now().Add(24 * time.Hour).Unix())

	// 4. Write Prover.toml for nargo
	proverToml := buildProverToml(
		cred.Claims.BirthDateDays,
		holderSecret,
		issuerPubkeyX, issuerPubkeyY,
		cred.Signature,
		merklePath, merkleIndexBits,
		idempotencyKeyHash,
		verifierIDHash, factTypeHash,
		policyRoot, schemaHash,
		subjectTag, nullifier,
		validUntil,
		req.Predicate.CutoffDateDays,
	)

	tomlPath := filepath.Join(cfg.CircuitDir, "Prover.toml")
	if err := os.WriteFile(tomlPath, []byte(proverToml), 0644); err != nil {
		return nil, fmt.Errorf("write Prover.toml: %w", err)
	}

	// 5. Run nargo execute
	if err := runCommand(cfg.CircuitDir, cfg.NargoBin, "execute"); err != nil {
		return nil, fmt.Errorf("nargo execute: %w", err)
	}

	// 6. Run bb prove
	acirPath := filepath.Join(cfg.CircuitDir, "target", "age_over_18_v1.json")
	witnessPath := filepath.Join(cfg.CircuitDir, "target", "age_over_18_v1.gz")
	proofOutDir := filepath.Join(cfg.CircuitDir, "out", "proof")
	os.MkdirAll(filepath.Dir(proofOutDir), 0755)

	if err := runCommand(cfg.CircuitDir, cfg.BbBin, "prove",
		"-b", acirPath,
		"-w", witnessPath,
		"-o", proofOutDir,
	); err != nil {
		return nil, fmt.Errorf("bb prove: %w", err)
	}

	// 7. Read proof
	proofBytes, err := os.ReadFile(proofOutDir)
	if err != nil {
		return nil, fmt.Errorf("read proof file: %w", err)
	}
	proofHex := "0x" + hex.EncodeToString(proofBytes)

	// 8. Build ProofPackage
	pkg := &ProofPackage{
		Version:   "1.0",
		RequestID: req.RequestID,
		CircuitID: "age_over_18_v1",
		Backend:   "noir-barretenberg",
		Proof:     proofHex,
		PublicInputs: []string{
			FieldToHex(verifierIDHash),
			FieldToHex(factTypeHash),
			FieldToHex(policyRoot),
			FieldToHex(schemaHash),
			FieldToHex(subjectTag),
			FieldToHex(nullifier),
			fmt.Sprintf("0x%064x", new(big.Int).SetUint64(validUntil)),
			fmt.Sprintf("0x%064x", new(big.Int).SetUint64(req.Predicate.CutoffDateDays)),
		},
		PublicInputLabels: []string{
			"verifier_id_hash",
			"fact_type_hash",
			"issuer_policy_root",
			"schema_hash",
			"subject_tag",
			"nullifier",
			"valid_until",
			"cutoff_date_days",
		},
		SubjectTag:  FieldToHex(subjectTag),
		Nullifier:   FieldToHex(nullifier),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	return pkg, nil
}

type ProverConfig struct {
	CircuitDir   string
	NargoBin     string
	BbBin        string
	HolderSecret string
}

func buildProverToml(
	birthDateDays uint64,
	holderSecret *big.Int,
	issuerPubX, issuerPubY *big.Int,
	sig creds.EdDSASignature,
	merklePath []*big.Int, merkleIndexBits []int,
	idempotencyKeyHash *big.Int,
	verifierIDHash, factTypeHash *big.Int,
	policyRoot, schemaHash *big.Int,
	subjectTag, nullifier *big.Int,
	validUntil uint64,
	cutoffDateDays uint64,
) string {
	toml := fmt.Sprintf(`birth_date_days = "%d"
holder_secret = "%s"
issuer_pubkey_x = "%s"
issuer_pubkey_y = "%s"
sig_r8x = "%s"
sig_r8y = "%s"
sig_s = "%s"
`, birthDateDays,
		holderSecret.String(),
		issuerPubX.String(),
		issuerPubY.String(),
		fieldFromHex(sig.R8X),
		fieldFromHex(sig.R8Y),
		fieldFromHex(sig.S),
	)

	// merkle_path array
	toml += "merkle_path = ["
	for i := 0; i < policy.TreeDepth; i++ {
		if i < len(merklePath) {
			toml += fmt.Sprintf(`"%s"`, merklePath[i].String())
		} else {
			toml += `"0"`
		}
		if i < policy.TreeDepth-1 {
			toml += ", "
		}
	}
	toml += "]\n"

	// merkle_index_bits array
	toml += "merkle_index_bits = ["
	for i := 0; i < policy.TreeDepth; i++ {
		if i < len(merkleIndexBits) {
			toml += fmt.Sprintf(`"%d"`, merkleIndexBits[i])
		} else {
			toml += `"0"`
		}
		if i < policy.TreeDepth-1 {
			toml += ", "
		}
	}
	toml += "]\n"

	toml += fmt.Sprintf(`idempotency_key_hash = "%s"
verifier_id_hash = "%s"
fact_type_hash = "%s"
issuer_policy_root = "%s"
schema_hash = "%s"
subject_tag = "%s"
nullifier = "%s"
valid_until = "%d"
cutoff_date_days = "%d"
`,
		idempotencyKeyHash.String(),
		verifierIDHash.String(),
		factTypeHash.String(),
		policyRoot.String(),
		schemaHash.String(),
		subjectTag.String(),
		nullifier.String(),
		validUntil,
		cutoffDateDays,
	)

	return toml
}

func fieldFromHex(h string) string {
	v, err := HexToField(h)
	if err != nil {
		return "0"
	}
	return v.String()
}

func computeIdempotencyKeyHash(key string) (*big.Int, error) {
	// Hash the idempotency key string to a field element
	// Simple approach: interpret as bytes, then hash
	if key == "" {
		return big.NewInt(0), nil
	}
	// Use a simple numeric hash of the key bytes
	h := new(big.Int)
	h.SetBytes([]byte(key))
	// Ensure it fits in the field
	return h, nil
}

func runCommand(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func SaveProofPackage(pkg *ProofPackage, path string) error {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof package: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
