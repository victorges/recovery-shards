package command

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

type ShareInfo struct {
	Identifier byte
	Data       []byte
}

func Recover(shares []ShareInfo) error {
	// Reconstruct complete shares
	completeShares := make([][]byte, len(shares))
	for i, share := range shares {
		completeShare := make([]byte, len(share.Data)+shamir.ShareOverhead)
		copy(completeShare, share.Data)
		completeShare[len(share.Data)] = share.Identifier
		completeShares[i] = completeShare
	}

	recoveredEntropy, err := shamir.Combine(completeShares)
	if err != nil {
		return fmt.Errorf("failed to recover secret: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(recoveredEntropy)
	if err != nil {
		return fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	fmt.Println("Recovered mnemonic phrase:")
	fmt.Printf("\n%s\n", mnemonic)
	return nil
}
