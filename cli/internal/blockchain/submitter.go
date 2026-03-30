package blockchain

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type SubmitConfig struct {
	RPCURL              string
	PrivateKey          string
	FactRegistryAddress string
	ChainID             *big.Int
}

type SubmitParams struct {
	Proof            []byte
	PublicInputs     [][32]byte
	VerifierIDHash   [32]byte
	SubjectTag       [32]byte
	FactTypeHash     [32]byte
	IssuerPolicyRoot [32]byte
	SchemaHash       [32]byte
	Nullifier        [32]byte
	ValidUntil       uint64
}

// SubmitFact sends the proof to FactRegistry.submitVerifiedFact
func SubmitFact(cfg SubmitConfig, params SubmitParams) (string, error) {
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return "", fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	privKeyHex := strings.TrimPrefix(cfg.PrivateKey, "0x")
	privateKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKey)

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", fmt.Errorf("suggest gas price: %w", err)
	}

	contractAddr := common.HexToAddress(cfg.FactRegistryAddress)

	// ABI encode the function call
	factRegistryABI := getFactRegistryABI()
	inputData, err := factRegistryABI.Pack("submitVerifiedFact",
		params.Proof,
		params.PublicInputs,
		params.VerifierIDHash,
		params.SubjectTag,
		params.FactTypeHash,
		params.IssuerPolicyRoot,
		params.SchemaHash,
		params.Nullifier,
		params.ValidUntil,
	)
	if err != nil {
		return "", fmt.Errorf("ABI encode: %w", err)
	}

	tx := types.NewTransaction(
		nonce,
		contractAddr,
		big.NewInt(0),
		uint64(3000000), // gas limit
		gasPrice,
		inputData,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(cfg.ChainID), privateKey)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	return signedTx.Hash().Hex(), nil
}

// HexToBytes32 converts a 0x-prefixed hex string to [32]byte
func HexToBytes32(h string) ([32]byte, error) {
	var result [32]byte
	h = strings.TrimPrefix(h, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return result, err
	}
	// Right-pad or left-pad to 32 bytes
	if len(b) > 32 {
		b = b[:32]
	}
	copy(result[32-len(b):], b)
	return result, nil
}

func getFactRegistryABI() abi.ABI {
	const factRegistryABIJSON = `[{
		"inputs": [
			{"name": "proof", "type": "bytes"},
			{"name": "publicInputs", "type": "bytes32[]"},
			{"name": "verifierIdHash", "type": "bytes32"},
			{"name": "subjectTag", "type": "bytes32"},
			{"name": "factTypeHash", "type": "bytes32"},
			{"name": "issuerPolicyRoot", "type": "bytes32"},
			{"name": "schemaHash", "type": "bytes32"},
			{"name": "nullifier", "type": "bytes32"},
			{"name": "validUntil", "type": "uint64"}
		],
		"name": "submitVerifiedFact",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}]`
	parsed, _ := abi.JSON(strings.NewReader(factRegistryABIJSON))
	return parsed
}
