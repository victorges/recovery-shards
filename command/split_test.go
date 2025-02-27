package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

func TestSplit(t *testing.T) {
	testCases := []struct {
		name      string
		mnemonic  string
		total     int
		threshold int
	}{
		{
			name:      "2-out-of-2",
			mnemonic:  "goose apple ecology ill reduce poem wish olive guitar health run chimney limb village nice dismiss razor meat property try talent toward clever cherry",
			total:     2,
			threshold: 2,
		},
		{
			name:      "2-out-of-3",
			mnemonic:  "happy wet injury knee buddy anger ordinary ketchup bread oxygen puzzle hip mechanic sunny monitor exit join spy awkward degree island task eternal sniff",
			total:     3,
			threshold: 2,
		},
		{
			name:      "3-out-of-5",
			mnemonic:  "cabin journey merry actor derive blanket crowd infant dove window mixture story monitor cloth increase defy erupt chair voice hood immense wire awkward fluid",
			total:     5,
			threshold: 3,
		},
		{
			name:      "5-out-of-7",
			mnemonic:  "cabin journey merry actor derive blanket crowd infant dove window mixture story monitor cloth increase defy erupt chair voice hood immense wire awkward fluid",
			total:     7,
			threshold: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Split the mnemonic
			shares, err := Split(tc.mnemonic, tc.total, tc.threshold)
			require.NoError(t, err)
			require.Len(t, shares, tc.total)

			// Verify all shares have valid identifiers and mnemonics
			for _, share := range shares {
				require.NotNil(t, share.Identifier)
				require.True(t, bip39.IsMnemonicValid(share.Mnemonic))
			}

			// Verify the shares
			err = VerifyShares(tc.mnemonic, shares, tc.threshold)
			require.NoError(t, err)
		})
	}
}

func TestSplitErrors(t *testing.T) {
	testCases := []struct {
		name      string
		mnemonic  string
		total     int
		threshold int
		errMsg    string
	}{
		{
			name:      "invalid_mnemonic",
			mnemonic:  "not a valid mnemonic",
			total:     3,
			threshold: 2,
			errMsg:    "invalid mnemonic phrase",
		},
		{
			name:      "threshold_greater_than_total",
			mnemonic:  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			total:     2,
			threshold: 3,
			errMsg:    "parts cannot be less than threshold",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Split(tc.mnemonic, tc.total, tc.threshold)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}
