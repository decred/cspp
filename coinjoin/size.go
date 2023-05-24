package coinjoin

import (
	"github.com/decred/dcrd/wire"
)

const (
	redeemP2PKHv0SigScriptSize = 1 + 73 + 1 + 33
	p2pkhv0PkScriptSize        = 1 + 1 + 1 + 20 + 1 + 1
)

func estimateP2PKHv0SerializeSize(inputs, outputs int, hasChange bool) int {
	// Sum the estimated sizes of the inputs and outputs.
	txInsSize := inputs * estimateInputSize(redeemP2PKHv0SigScriptSize)
	txOutsSize := outputs * estimateOutputSize(p2pkhv0PkScriptSize)

	changeSize := 0
	if hasChange {
		changeSize = estimateOutputSize(p2pkhv0PkScriptSize)
		outputs++
	}

	// 12 additional bytes are for version, locktime and expiry.
	return 12 + (2 * wire.VarIntSerializeSize(uint64(inputs))) +
		wire.VarIntSerializeSize(uint64(outputs)) +
		txInsSize + txOutsSize + changeSize
}

// estimateInputSize returns the worst case serialize size estimate for a tx input
func estimateInputSize(scriptSize int) int {
	return 32 + // previous tx
		4 + // output index
		1 + // tree
		8 + // amount
		4 + // block height
		4 + // block index
		wire.VarIntSerializeSize(uint64(scriptSize)) + // size of script
		scriptSize + // script itself
		4 // sequence
}

// estimateOutputSize returns the worst case serialize size estimate for a tx output
func estimateOutputSize(scriptSize int) int {
	return 8 + // previous tx
		2 + // version
		wire.VarIntSerializeSize(uint64(scriptSize)) + // size of script
		scriptSize // script itself
}

func estimateIsStandardSize(inputs, outputs int) bool {
	const maxSize = 100000

	estimated := estimateP2PKHv0SerializeSize(inputs, outputs, false)
	return estimated <= maxSize
}
