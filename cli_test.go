package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
	"github.com/victorges/recovery-shards/model"
)

func TestCLIEndToEnd(t *testing.T) {
	// Generate a test mnemonic
	entropy, err := bip39.NewEntropy(256)
	require.NoError(t, err)
	originalMnemonic, err := bip39.NewMnemonic(entropy)
	require.NoError(t, err)

	testCases := []struct {
		name, total, threshold string
	}{
		{
			name:      "2-out-of-2",
			total:     "2",
			threshold: "2",
		},
		{
			name:      "2-out-of-3",
			total:     "3",
			threshold: "2",
		},
		{
			name:      "3-out-of-5",
			total:     "5",
			threshold: "3",
		},
		{
			name:      "5-out-of-7",
			total:     "7",
			threshold: "5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test directory
			testDir := t.TempDir()

			// Write mnemonic to input file
			mnemonicFile := filepath.Join(testDir, "mnemonic.txt")
			err := os.WriteFile(mnemonicFile, []byte(originalMnemonic), 0644)
			require.NoError(t, err)

			// Test split command with directory output
			sharesDir := filepath.Join(testDir, "shares")
			err = RunCLI([]string{
				"recovery-shards",
				"split",
				"-n", tc.total,
				"-k", tc.threshold,
				"-in", mnemonicFile,
				"-out", sharesDir + "/",
			})
			require.NoError(t, err)

			// Test split command with single file output
			sharesFile := filepath.Join(testDir, "shares.txt")
			err = RunCLI([]string{
				"recovery-shards",
				"split",
				"-n", tc.total,
				"-k", tc.threshold,
				"-in", mnemonicFile,
				"-out", sharesFile,
			})
			require.NoError(t, err)

			// Test recover command from directory
			err = RunCLI([]string{
				"recovery-shards",
				"recover",
				"-in", sharesDir,
			})
			require.NoError(t, err)

			// Test recover command from file
			err = RunCLI([]string{
				"recovery-shards",
				"recover",
				"-in", sharesFile,
			})
			require.NoError(t, err)
		})
	}
}

func TestCLIErrors(t *testing.T) {
	testDir := t.TempDir()

	t.Run("invalid_mnemonic", func(t *testing.T) {
		mnemonicFile := filepath.Join(testDir, "invalid.txt")
		err := os.WriteFile(mnemonicFile, []byte("not a valid mnemonic"), 0644)
		require.NoError(t, err)

		err = RunCLI([]string{
			"recovery-shards",
			"split",
			"-n", "3",
			"-k", "2",
			"-in", mnemonicFile,
		})
		require.Error(t, err)
	})

	t.Run("invalid_threshold", func(t *testing.T) {
		err := RunCLI([]string{
			"recovery-shards",
			"split",
			"-n", "2",
			"-k", "3", // threshold > total
			"-in", "nonexistent.txt",
		})
		require.Error(t, err)
	})

	t.Run("missing_input", func(t *testing.T) {
		err := RunCLI([]string{
			"recovery-shards",
			"recover",
		})
		require.Error(t, err)
	})
}

func TestInvalidInputs(t *testing.T) {
	t.Run("invalid_mnemonic", func(t *testing.T) {
		invalidMnemonic := "not a valid mnemonic phrase"
		tmpFile := filepath.Join(t.TempDir(), "invalid.txt")
		err := os.WriteFile(tmpFile, []byte(invalidMnemonic), 0644)
		require.NoError(t, err)

		err = RunCLI([]string{
			"recovery-shards",
			"split",
			"-n", "3",
			"-k", "2",
			"-in", tmpFile,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "mnemonic must contain exactly 24 words")
	})

	t.Run("invalid_share_count", func(t *testing.T) {
		entropy, err := bip39.NewEntropy(256)
		require.NoError(t, err)
		mnemonic, err := bip39.NewMnemonic(entropy)
		require.NoError(t, err)

		tmpFile := filepath.Join(t.TempDir(), "mnemonic.txt")
		err = os.WriteFile(tmpFile, []byte(mnemonic), 0644)
		require.NoError(t, err)

		err = RunCLI([]string{
			"recovery-shards",
			"split",
			"-n", "1",
			"-k", "2",
			"-in", tmpFile,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parts cannot be less than threshold")
	})

	t.Run("insufficient_shares", func(t *testing.T) {
		entropy, err := bip39.NewEntropy(256)
		require.NoError(t, err)
		mnemSh, err := model.NewMnemonicShareFromShamir(append(entropy, 0x01))
		require.NoError(t, err)

		sharesFile := filepath.Join(t.TempDir(), "shares.txt")
		err = os.WriteFile(sharesFile, []byte(mnemSh.String()), 0644)
		require.NoError(t, err)

		err = RunCLI([]string{
			"recovery-shards",
			"recover",
			"-in", sharesFile,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least two shares are required")
	})
}
