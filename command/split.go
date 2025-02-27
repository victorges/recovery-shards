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

func VerifyShares(originalMnemonic string, shares []model.MnemonicShare, k int) error {
	if len(shares) < k {
		return fmt.Errorf("not enough shares to verify")
	}

	for _, combination := range generateCombinations(shares, k) {
		mnemonic, err := Recover(combination)
		if err != nil {
			return fmt.Errorf("failed to recover mnemonic: %w", err)
		}
		if mnemonic != originalMnemonic {
			return fmt.Errorf("mnemonic does not match")
		}
	}

	return nil
}

func generateCombinations(shares []model.MnemonicShare, k int) [][]model.MnemonicShare {
	if k > len(shares) {
		return [][]model.MnemonicShare{}
	} else if k == 0 {
		return [][]model.MnemonicShare{{}}
	}

	combsWith := generateCombinations(shares[1:], k-1)
	for i, comb := range combsWith {
		combsWith[i] = append([]model.MnemonicShare{shares[0]}, comb...)
	}
	combsWithout := generateCombinations(shares[1:], k)
	return append(combsWith, combsWithout...)
}
