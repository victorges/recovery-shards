package command

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
	"github.com/victorges/recovery-shards/model"
)

func Split(mnemonic string, n, k int) ([]model.MnemonicShare, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to get entropy: %w", err)
	}

	shares, err := shamir.Split(entropy, n, k)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}

	result := make([]model.MnemonicShare, len(shares))
	for i, share := range shares {
		mnemShare, err := model.NewMnemonicShareFromShamir(share)
		if err != nil {
			return nil, fmt.Errorf("failed to create mnemonic for share %d: %w", i+1, err)
		}
		result[i] = mnemShare
	}

	return result, nil
}
