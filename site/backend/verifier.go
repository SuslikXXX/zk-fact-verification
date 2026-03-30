package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type FactResult struct {
	Exists           bool   `json:"exists"`
	VerifierIDHash   string `json:"verifier_id_hash,omitempty"`
	SubjectTag       string `json:"subject_tag,omitempty"`
	FactTypeHash     string `json:"fact_type_hash,omitempty"`
	IssuerPolicyRoot string `json:"issuer_policy_root,omitempty"`
	SchemaHash       string `json:"schema_hash,omitempty"`
	Nullifier        string `json:"nullifier,omitempty"`
	VerifiedAt       string `json:"verified_at,omitempty"`
	ValidUntil       string `json:"valid_until,omitempty"`
	Submitter        string `json:"submitter,omitempty"`
	IsValid          bool   `json:"is_valid"`
	FactKey          string `json:"fact_key,omitempty"`
}

func lookupFactOnChain(rpcURL, factRegistryAddr, verifierIDHashHex, subjectTagHex, factTypeHashHex string) (*FactResult, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)
	parsedABI := getFactABI()

	vid, err := hexToBytes32(verifierIDHashHex)
	if err != nil {
		return nil, fmt.Errorf("parse verifier_id_hash: %w", err)
	}
	st, err := hexToBytes32(subjectTagHex)
	if err != nil {
		return nil, fmt.Errorf("parse subject_tag: %w", err)
	}
	fth, err := hexToBytes32(factTypeHashHex)
	if err != nil {
		return nil, fmt.Errorf("parse fact_type_hash: %w", err)
	}

	// Call getFact
	data, err := parsedABI.Pack("getFact", vid, st, fth)
	if err != nil {
		return nil, fmt.Errorf("ABI pack: %w", err)
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call contract: %w", err)
	}

	// Decode tuple
	out, err := parsedABI.Methods["getFact"].Outputs.Unpack(result)
	if err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	type factStruct struct {
		VerifierIdHash   [32]byte
		SubjectTag       [32]byte
		FactTypeHash     [32]byte
		IssuerPolicyRoot [32]byte
		SchemaHash       [32]byte
		Nullifier        [32]byte
		VerifiedAt       uint64
		ValidUntil       uint64
		Submitter        common.Address
		Exists           bool
	}

	// ABI returns a struct as anonymous tuple
	raw := out[0]
	s, ok := raw.(struct {
		VerifierIdHash   [32]byte       `json:"verifierIdHash"`
		SubjectTag       [32]byte       `json:"subjectTag"`
		FactTypeHash     [32]byte       `json:"factTypeHash"`
		IssuerPolicyRoot [32]byte       `json:"issuerPolicyRoot"`
		SchemaHash       [32]byte       `json:"schemaHash"`
		Nullifier        [32]byte       `json:"nullifier"`
		VerifiedAt       uint64         `json:"verifiedAt"`
		ValidUntil       uint64         `json:"validUntil"`
		Submitter        common.Address `json:"submitter"`
		Exists           bool           `json:"exists"`
	})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", raw)
	}

	now := uint64(time.Now().Unix())
	isValid := s.Exists && (s.ValidUntil == 0 || now <= s.ValidUntil)

	// Compute fact_key for reference
	packed := make([]byte, 96)
	copy(packed[0:32], s.VerifierIdHash[:])
	copy(packed[32:64], s.SubjectTag[:])
	copy(packed[64:96], s.FactTypeHash[:])
	factKey := common.BytesToHash(common.CopyBytes(packed)) // simplified

	res := &FactResult{
		Exists:           s.Exists,
		VerifierIDHash:   "0x" + hex.EncodeToString(s.VerifierIdHash[:]),
		SubjectTag:       "0x" + hex.EncodeToString(s.SubjectTag[:]),
		FactTypeHash:     "0x" + hex.EncodeToString(s.FactTypeHash[:]),
		IssuerPolicyRoot: "0x" + hex.EncodeToString(s.IssuerPolicyRoot[:]),
		SchemaHash:       "0x" + hex.EncodeToString(s.SchemaHash[:]),
		Nullifier:        "0x" + hex.EncodeToString(s.Nullifier[:]),
		Submitter:        s.Submitter.Hex(),
		IsValid:          isValid,
		FactKey:          factKey.Hex(),
	}

	if s.Exists {
		res.VerifiedAt = time.Unix(int64(s.VerifiedAt), 0).UTC().Format(time.RFC3339)
		res.ValidUntil = time.Unix(int64(s.ValidUntil), 0).UTC().Format(time.RFC3339)
	}

	return res, nil
}

func hexToBytes32(h string) ([32]byte, error) {
	var result [32]byte
	h = strings.TrimPrefix(h, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return result, err
	}
	if len(b) > 32 {
		b = b[:32]
	}
	copy(result[32-len(b):], b)
	return result, nil
}

func getFactABI() abi.ABI {
	const abiJSON = `[
		{
			"inputs": [
				{"name": "verifierIdHash", "type": "bytes32"},
				{"name": "subjectTag", "type": "bytes32"},
				{"name": "factTypeHash", "type": "bytes32"}
			],
			"name": "getFact",
			"outputs": [
				{
					"components": [
						{"name": "verifierIdHash", "type": "bytes32"},
						{"name": "subjectTag", "type": "bytes32"},
						{"name": "factTypeHash", "type": "bytes32"},
						{"name": "issuerPolicyRoot", "type": "bytes32"},
						{"name": "schemaHash", "type": "bytes32"},
						{"name": "nullifier", "type": "bytes32"},
						{"name": "verifiedAt", "type": "uint64"},
						{"name": "validUntil", "type": "uint64"},
						{"name": "submitter", "type": "address"},
						{"name": "exists", "type": "bool"}
					],
					"name": "",
					"type": "tuple"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{"name": "verifierIdHash", "type": "bytes32"},
				{"name": "subjectTag", "type": "bytes32"},
				{"name": "factTypeHash", "type": "bytes32"}
			],
			"name": "isFactValid",
			"outputs": [{"name": "", "type": "bool"}],
			"stateMutability": "view",
			"type": "function"
		}
	]`
	parsed, _ := abi.JSON(strings.NewReader(abiJSON))
	return parsed
}

// unused import guard
var _ = new(big.Int)
