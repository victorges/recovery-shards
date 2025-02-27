package model

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

func TestMnemonicShare(t *testing.T) {
	// Generate a valid mnemonic for testing
	entropy, err := bip39.NewEntropy(256)
	require.NoError(t, err)
	mnemSh, err := NewMnemonicShareFromShamir(append(entropy, 0xee))
	require.NoError(t, err)

	t.Run("create_valid_share", func(t *testing.T) {
		share, err := NewMnemonicShare(mnemSh.Identifier, mnemSh.Mnemonic)
		require.NoError(t, err)
		assert.Equal(t, mnemSh.Identifier, share.Identifier)
		assert.Equal(t, mnemSh.Mnemonic, share.Mnemonic)
	})

	t.Run("create_invalid_mnemonic", func(t *testing.T) {
		identifier, err := hex.DecodeString("01")
		require.NoError(t, err)

		_, err = NewMnemonicShare(identifier, "not a valid mnemonic")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid mnemonic")
	})

	t.Run("shamir_conversion_roundtrip", func(t *testing.T) {
		// Create a share from Shamir
		entropy, err := bip39.NewEntropy(256)
		require.NoError(t, err)

		// Create a mock Shamir share (entropy + identifier)
		identifier := []byte{0x01}
		shamirShare := append(entropy, identifier...)

		// Convert to MnemonicShare
		share, err := NewMnemonicShareFromShamir(shamirShare)
		require.NoError(t, err)

		// Convert back to Shamir
		convertedShamir, err := share.ToShamir()
		require.NoError(t, err)

		// Verify the conversion preserved the data
		assert.Equal(t, shamirShare, convertedShamir)
	})

	t.Run("invalid_shamir_share", func(t *testing.T) {
		// Test with too short share
		_, err := NewMnemonicShareFromShamir([]byte{0x01})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid share length")
	})

	t.Run("invalid_check_byte", func(t *testing.T) {
		// Create a valid share
		identifier, err := hex.DecodeString("01")
		require.NoError(t, err)

		// Add a check byte
		identifierWithCheck := append(identifier, 0xFF) // Invalid check byte

		share := MnemonicShare{
			Identifier: identifierWithCheck,
			Mnemonic:   mnemSh.Mnemonic,
		}

		// Try to convert to Shamir
		_, err = share.ToShamir()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid check byte")
	})
}

func TestXorCheckByte(t *testing.T) {
	testCases := []struct {
		name       string
		identifier []byte
		data       []byte
		expected   byte
	}{
		{
			name:       "simple_case",
			identifier: []byte{0x01},
			data:       []byte{0x02, 0x03},
			expected:   0x00, // 0x01 ^ 0x02 ^ 0x03 = 0x00
		},
		{
			name:       "empty_data",
			identifier: []byte{0x01},
			data:       []byte{},
			expected:   0x01, // 0x01 = 0x01
		},
		{
			name:       "empty_identifier",
			identifier: []byte{},
			data:       []byte{0x01, 0x02},
			expected:   0x03, // 0x01 ^ 0x02 = 0x03
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := checksumByte(tc.identifier, tc.data)
			assert.Equal(t, tc.expected, result)
		})
	}
}
