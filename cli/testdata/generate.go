// +build ignore

// generate.go - creates real test data with EdDSA keys and valid Merkle tree
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func main() {
	// 1. Generate issuer EdDSA keypair (BabyJubJub)
	issuerPrivKey := babyjub.NewRandPrivKey()
	issuerPubKey := issuerPrivKey.Public()
	fmt.Printf("Issuer privkey: %s\n", issuerPrivKey)
	fmt.Printf("Issuer pubkey X: %s\n", issuerPubKey.X.String())
	fmt.Printf("Issuer pubkey Y: %s\n", issuerPubKey.Y.String())

	// 2. Create credential data
	birthDateDays := big.NewInt(11323) // ~2001-01-01
	// BN254 scalar field prime
	bnPrime0, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	schemaHash := new(big.Int).Mod(hexToBig("0x1111111111111111111111111111111111111111111111111111111111111111"), bnPrime0)

	// 3. Compute credential hash = Poseidon(pubkey_x, pubkey_y, birth_date_days, schema_hash)
	credHash, _ := poseidon.Hash([]*big.Int{issuerPubKey.X, issuerPubKey.Y, birthDateDays, schemaHash})
	fmt.Printf("Credential hash: %s\n", credHash.String())

	// 4. Sign credential hash with EdDSA
	sig := issuerPrivKey.SignPoseidon(credHash)
	fmt.Printf("Sig R8.X: %s\n", sig.R8.X.String())
	fmt.Printf("Sig R8.Y: %s\n", sig.R8.Y.String())
	fmt.Printf("Sig S: %s\n", sig.S.String())

	// Verify signature locally
	ok := issuerPubKey.VerifyPoseidon(credHash, sig)
	fmt.Printf("Signature valid: %v\n", ok)
	if !ok {
		fmt.Println("ERROR: signature verification failed!")
		os.Exit(1)
	}

	// 5. Build Merkle tree with this issuer
	// leaf = Poseidon(pubkey_x, pubkey_y)
	leaf, _ := poseidon.Hash([]*big.Int{issuerPubKey.X, issuerPubKey.Y})
	fmt.Printf("Leaf: 0x%064x\n", leaf)

	// Build tree depth=16 with 1 real leaf + padding zeros
	const depth = 16
	const maxLeaves = 1 << depth
	leaves := make([]*big.Int, maxLeaves)
	leaves[0] = leaf
	for i := 1; i < maxLeaves; i++ {
		leaves[i] = big.NewInt(0)
	}

	levels := make([][]*big.Int, depth+1)
	levels[0] = leaves
	for d := 0; d < depth; d++ {
		prev := levels[d]
		next := make([]*big.Int, len(prev)/2)
		for i := 0; i < len(next); i++ {
			h, _ := poseidon.Hash([]*big.Int{prev[2*i], prev[2*i+1]})
			next[i] = h
		}
		levels[d+1] = next
	}
	root := levels[depth][0]
	fmt.Printf("Merkle root: 0x%064x\n", root)

	// Get merkle path for leaf 0
	merklePath := make([]string, depth)
	merkleIndexBits := make([]int, depth)
	idx := 0
	for d := 0; d < depth; d++ {
		if idx%2 == 0 {
			merklePath[d] = levels[d][idx+1].String()
			merkleIndexBits[d] = 0
		} else {
			merklePath[d] = levels[d][idx-1].String()
			merkleIndexBits[d] = 1
		}
		idx /= 2
	}

	// 6. Compute subject_tag and nullifier
	// BN254 scalar field prime
	bnPrime, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	holderSecret := hexToBig("0x00deadbeef00000000000000000000000000000000000000000000000000001")
	verifierIDHash := new(big.Int).Mod(hexToBig("0x2222222222222222222222222222222222222222222222222222222222222222"), bnPrime)
	factTypeHash := new(big.Int).Mod(hexToBig("0x3333333333333333333333333333333333333333333333333333333333333333"), bnPrime)
	idempotencyKeyHash := new(big.Int).SetBytes([]byte("session-2026-03-30-001"))

	subjectTag, _ := poseidon.Hash([]*big.Int{holderSecret, verifierIDHash})
	nullifier, _ := poseidon.Hash([]*big.Int{holderSecret, verifierIDHash, factTypeHash, idempotencyKeyHash})

	fmt.Printf("Subject tag: 0x%064x\n", subjectTag)
	fmt.Printf("Nullifier: 0x%064x\n", nullifier)

	cutoffDateDays := uint64(13879) // ~2008-01-01 (18 years before ~2026)
	validUntil := uint64(1774867200)

	// 7. Write credential.json
	credential := map[string]interface{}{
		"version":       "1.0",
		"credential_id": "urn:uuid:test-cred-001",
		"type":          []string{"VerifiableCredential", "AgeCredential"},
		"issuer": map[string]string{
			"did":      "did:web:gov.example.ru",
			"kid":      "zk-key-1",
			"pubkey_x": fmt.Sprintf("0x%064x", issuerPubKey.X),
			"pubkey_y": fmt.Sprintf("0x%064x", issuerPubKey.Y),
		},
		"subject": map[string]string{
			"did":                "did:key:holder-test-001",
			"binding_commitment": fmt.Sprintf("0x%064x", holderSecret),
		},
		"issuance_date":   "2026-03-01T09:00:00Z",
		"expiration_date": "2031-03-01T09:00:00Z",
		"schema_id":       "vc.age.v1",
		"schema_hash":     fmt.Sprintf("0x%064x", schemaHash),
		"claims": map[string]interface{}{
			"birth_date_days": 11323,
		},
		"revocation": map[string]interface{}{
			"status_list_id": "revocation-list-2026-03",
			"status_index":   481,
		},
		"signature": map[string]string{
			"alg": "eddsa-bn254-poseidon",
			"r8x": fmt.Sprintf("0x%064x", sig.R8.X),
			"r8y": fmt.Sprintf("0x%064x", sig.R8.Y),
			"s":   fmt.Sprintf("0x%064x", sig.S),
		},
	}
	writeJSON("credential.json", credential)

	// 8. Write issuer_policy.json
	issuerPolicy := map[string]interface{}{
		"version":  "1.0",
		"policy_id": "age-ru-2026-03",
		"hash_alg": "poseidon",
		"depth":    depth,
		"root":     fmt.Sprintf("0x%064x", root),
		"issuers": []map[string]string{
			{
				"issuer_id":   "did:web:gov.example.ru",
				"pubkey_hash": fmt.Sprintf("0x%064x", leaf),
				"leaf":        fmt.Sprintf("0x%064x", leaf),
			},
		},
	}
	writeJSON("issuer_policy.json", issuerPolicy)

	// 9. Write verification_request.json
	request := map[string]interface{}{
		"version":          "1.0",
		"request_id":       "urn:uuid:req-test-001",
		"verifier_id":      "did:web:shop.example.com",
		"verifier_id_hash": fmt.Sprintf("0x%064x", verifierIDHash),
		"fact_type":        "age_over_18",
		"fact_type_hash":   fmt.Sprintf("0x%064x", factTypeHash),
		"purpose":          "age_check",
		"idempotency_key":  "session-2026-03-30-001",
		"issued_at":        "2026-03-30T10:00:00Z",
		"expires_at":       "2027-03-30T10:05:00Z",
		"schema_id":        "vc.age.v1",
		"schema_hash":      fmt.Sprintf("0x%064x", schemaHash),
		"circuit_id":       "age_over_18_v1",
		"predicate": map[string]interface{}{
			"type":             "birth_date_lte_cutoff",
			"cutoff_date_days": cutoffDateDays,
		},
		"issuer_policy": map[string]interface{}{
			"root":           fmt.Sprintf("0x%064x", root),
			"snapshot_block": 0,
			"issuers": []map[string]string{
				{
					"issuer_id":   "did:web:gov.example.ru",
					"pubkey_hash": fmt.Sprintf("0x%064x", leaf),
					"leaf":        fmt.Sprintf("0x%064x", leaf),
				},
			},
		},
		"chain": map[string]interface{}{
			"chain_id":                31337,
			"fact_registry_address":   "0x0000000000000000000000000000000000000000",
			"issuer_registry_address": "0x0000000000000000000000000000000000000000",
		},
		"response": map[string]string{
			"mode":         "https_post",
			"callback_url": "https://shop.example.com/api/zk/notify",
		},
	}
	writeJSON("verification_request.json", request)

	// 10. Write Prover.toml directly for nargo test
	proverToml := fmt.Sprintf(`birth_date_days = "%d"
holder_secret = "%s"
issuer_pubkey_x = "%s"
issuer_pubkey_y = "%s"
sig_r8x = "%s"
sig_r8y = "%s"
sig_s = "%s"
`, birthDateDays.Uint64(),
		holderSecret.String(),
		issuerPubKey.X.String(),
		issuerPubKey.Y.String(),
		sig.R8.X.String(),
		sig.R8.Y.String(),
		sig.S.String(),
	)

	proverToml += "merkle_path = ["
	for i := 0; i < depth; i++ {
		proverToml += fmt.Sprintf(`"%s"`, merklePath[i])
		if i < depth-1 {
			proverToml += ", "
		}
	}
	proverToml += "]\n"

	proverToml += "merkle_index_bits = ["
	for i := 0; i < depth; i++ {
		proverToml += fmt.Sprintf(`"%d"`, merkleIndexBits[i])
		if i < depth-1 {
			proverToml += ", "
		}
	}
	proverToml += "]\n"

	proverToml += fmt.Sprintf(`idempotency_key_hash = "%s"
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
		root.String(),
		schemaHash.String(),
		subjectTag.String(),
		nullifier.String(),
		validUntil,
		cutoffDateDays,
	)

	os.WriteFile("../../circuits/age_over_18_v1/Prover.toml", []byte(proverToml), 0644)
	fmt.Println("\nAll test data generated successfully!")
	fmt.Println("Files: credential.json, issuer_policy.json, verification_request.json")
	fmt.Println("Also: ../circuits/age_over_18_v1/Prover.toml")
}

func hexToBig(h string) *big.Int {
	if len(h) >= 2 && h[:2] == "0x" {
		h = h[2:]
	}
	v := new(big.Int)
	v.SetString(h, 16)
	return v
}

func writeJSON(path string, data interface{}) {
	b, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(path, b, 0644)
	fmt.Printf("Written: %s\n", path)
}
