package model

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

// MnemonicShare represents a single share of a split mnemonic phrase.
// It contains an identifier (with checksum) and the BIP39 mnemonic words.
type MnemonicShare struct {
	// Identifier contains the Shamir share ID bytes plus a checksum byte
	Identifier []byte
	// Mnemonic is a BIP39 mnemonic phrase representing the share data
	Mnemonic string
}

// NewMnemonicShare creates a new share with the given identifier and mnemonic.
// The identifier must be in hex format (0x optional) and include a valid
// checksum byte as its last byte. It can also have a colon at the end.
// The checksum byte is calculated by XORing all bytes of the identifier
// (excluding the checksum) with all bytes of the mnemonic's entropy.
//
// Returns an error if:
// - The identifier is not a valid hex string
// - The mnemonic is not a valid BIP39 mnemonic
// - The checksum byte in the identifier is invalid
func NewMnemonicShare(identifier, mnemonic string) (MnemonicShare, error) {
	identifier = strings.TrimSpace(identifier)
	identifier = strings.TrimSuffix(strings.TrimPrefix(identifier, "0x"), ":")
	identifierBytes, err := hex.DecodeString(identifier)
	if err != nil {
		return MnemonicShare{}, fmt.Errorf("invalid identifier: %w", err)
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return MnemonicShare{}, fmt.Errorf("invalid mnemonic")
	}
	share := MnemonicShare{
		Identifier: identifierBytes,
		Mnemonic:   mnemonic,
	}
	// Validate the checksum byte by attempting to convert to Shamir format
	if _, err := share.ToShamir(); err != nil {
		return MnemonicShare{}, fmt.Errorf("invalid share: %w", err)
	}
	return share, nil
}

// NewMnemonicShareFromShamir creates a MnemonicShare from raw Shamir share bytes.
// The input bytes should contain the share data followed by the Shamir overhead bytes.
//
// The function:
// 1. Splits the input into data and identifier parts
// 2. Calculates and appends a checksum byte to the identifier
// 3. Converts the data into a BIP39 mnemonic
//
// The checksum byte is calculated by XORing all bytes of the identifier
// with all bytes of the share data.
func NewMnemonicShareFromShamir(share []byte) (MnemonicShare, error) {
	if len(share) < 2 {
		return MnemonicShare{}, fmt.Errorf("invalid share length")
	}
	data := share[:len(share)-shamir.ShareOverhead]
	identifier := share[len(share)-shamir.ShareOverhead:]
	identifier = append(identifier, checksumByte(identifier, data))

	shareMnemonic, err := bip39.NewMnemonic(data)
	if err != nil {
		return MnemonicShare{}, fmt.Errorf("failed to generate mnemonic for share: %w", err)
	}
	return MnemonicShare{
		Identifier: identifier,
		Mnemonic:   shareMnemonic,
	}, nil
}

// ToShamir converts the MnemonicShare back to raw Shamir share bytes.
// It validates the checksum byte before returning the converted bytes.
//
// The function:
// 1. Extracts entropy from the BIP39 mnemonic
// 2. Validates the checksum byte in the identifier
// 3. Returns the concatenated entropy and identifier (without checksum)
//
// Returns an error if:
// - The mnemonic is invalid
// - The checksum byte validation fails
func (s MnemonicShare) ToShamir() ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(s.Mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	checksum := s.Identifier[len(s.Identifier)-1]
	onlyID := s.Identifier[:len(s.Identifier)-1]
	if expectedChecksum := checksumByte(onlyID, entropy); expectedChecksum != checksum {
		return nil, fmt.Errorf("invalid checksum on share %04x (expected: %02x, got: %02x)", s.Identifier, expectedChecksum, checksum)
	}
	return append(entropy, onlyID...), nil
}

// String returns a human-readable string representation of the share.
// The string includes the identifier in hexadecimal and the mnemonic phrase.
func (s MnemonicShare) String() string {
	return fmt.Sprintf("0x%04x: %s", s.Identifier, s.Mnemonic)
}

// checksumByte calculates a checksum byte by XORing all bytes in the identifier
// and data arrays. This provides a simple data integrity check for the share.
func checksumByte(identifier, data []byte) byte {
	checksum := byte(0)
	for _, b := range append(identifier, data...) {
		checksum ^= b
	}
	return checksum
}
