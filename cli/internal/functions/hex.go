package functions

import (
	"fmt"
	"math/big"
)

// HexToFieldElement converts a hex string (0x...) to a decimal string
func HexToFieldElement(hexStr string) string {
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}
	val := new(big.Int)
	val.SetString(hexStr, 16)
	return val.String()
}

// FieldToHex converts a big.Int to 0x-prefixed hex string
func FieldToHex(val *big.Int) string {
	return fmt.Sprintf("0x%064x", val)
}
