package command

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
	"github.com/victorges/recovery-shards/model"
)

func Recover(shares []model.MnemonicShare) (string, error) {
	// Convert mnemonics to entropy
	completeShares := make([][]byte, len(shares))
	for i, share := range shares {
		shamirShare, err := share.ToShamir()
		if err != nil {
			return "", fmt.Errorf("failed to convert share %d to shamir share: %w", i+1, err)
		}
		completeShares[i] = shamirShare
	}

	recoveredEntropy, err := shamir.Combine(completeShares)
	if err != nil {
		return "", fmt.Errorf("failed to recover secret: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(recoveredEntropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}
