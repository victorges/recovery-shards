package command

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

func Split(mnemonic string, n, k int, outputDir string) error {
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid mnemonic phrase")
	}

	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return fmt.Errorf("failed to get entropy: %w", err)
	}

	shares, err := shamir.Split(entropy, n, k)
	if err != nil {
		return fmt.Errorf("failed to split secret: %w", err)
	}

	fmt.Printf("Generated %d shares with a %d-out-of-%d threshold.\n", n, k, n)

	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		for i, share := range shares {
			identifier, data := splitShare(share)
			filename := filepath.Join(outputDir, fmt.Sprintf("share_%d.txt", i+1))
			content := fmt.Sprintf("Identifier: %02x\nData: %x", identifier, data)

			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write share file: %w", err)
			}
			fmt.Printf("Saved share %d to %s\n", i+1, filename)
		}
	} else {
		fmt.Println("Shares:")
		for i, share := range shares {
			identifier, data := splitShare(share)
			fmt.Printf("Share %d:\n\tIdentifier: %02x\n\tData: %x\n", i+1, identifier, data)
		}
	}

	return nil
}

// splitShare separates the data and identifier from a share
func splitShare(share []byte) (byte, []byte) {
	if len(share) < 2 {
		panic("invalid share length")
	}
	data := share[:len(share)-shamir.ShareOverhead]
	identifier := share[len(share)-shamir.ShareOverhead]
	return identifier, data
}
