package blockchain

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type VerifiedFact struct {
	VerifierIDHash   [32]byte
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

// LookupFact reads a VerifiedFact from FactRegistry by (verifierIdHash, subjectTag, factTypeHash)
func LookupFact(rpcURL, factRegistryAddr string, verifierIDHash, subjectTag, factTypeHash [32]byte) (*VerifiedFact, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)
	parsedABI := getFactReaderABI()

	data, err := parsedABI.Pack("getFact", verifierIDHash, subjectTag, factTypeHash)
	if err != nil {
		return nil, fmt.Errorf("ABI pack getFact: %w", err)
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call getFact: %w", err)
	}

	outputs, err := parsedABI.Unpack("getFact", result)
	if err != nil {
		return nil, fmt.Errorf("unpack getFact: %w", err)
	}

	if len(outputs) == 0 {
		return nil, fmt.Errorf("empty response from getFact")
	}

	// The output is a tuple struct
	type factTuple struct {
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

	// ABI decoding of struct
	var decoded factTuple
	err = parsedABI.UnpackIntoInterface(&decoded, "getFact", result)
	if err != nil {
		return nil, fmt.Errorf("decode fact tuple: %w", err)
	}

	return &VerifiedFact{
		VerifierIDHash:   decoded.VerifierIdHash,
		SubjectTag:       decoded.SubjectTag,
		FactTypeHash:     decoded.FactTypeHash,
		IssuerPolicyRoot: decoded.IssuerPolicyRoot,
		SchemaHash:       decoded.SchemaHash,
		Nullifier:        decoded.Nullifier,
		VerifiedAt:       decoded.VerifiedAt,
		ValidUntil:       decoded.ValidUntil,
		Submitter:        decoded.Submitter,
		Exists:           decoded.Exists,
	}, nil
}

// IsFactValid checks if a fact exists and is not expired
func IsFactValid(rpcURL, factRegistryAddr string, verifierIDHash, subjectTag, factTypeHash [32]byte) (bool, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return false, fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)
	parsedABI := getFactReaderABI()

	data, err := parsedABI.Pack("isFactValid", verifierIDHash, subjectTag, factTypeHash)
	if err != nil {
		return false, fmt.Errorf("ABI pack isFactValid: %w", err)
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return false, fmt.Errorf("call isFactValid: %w", err)
	}

	outputs, err := parsedABI.Unpack("isFactValid", result)
	if err != nil {
		return false, fmt.Errorf("unpack isFactValid: %w", err)
	}

	if len(outputs) > 0 {
		if val, ok := outputs[0].(bool); ok {
			return val, nil
		}
	}
	return false, nil
}

// ComputeFactKey computes keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash))
func ComputeFactKey(verifierIDHash, subjectTag, factTypeHash [32]byte) common.Hash {
	packed := make([]byte, 96)
	copy(packed[0:32], verifierIDHash[:])
	copy(packed[32:64], subjectTag[:])
	copy(packed[64:96], factTypeHash[:])
	return crypto.Keccak256Hash(packed)
}

func getFactReaderABI() abi.ABI {
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
