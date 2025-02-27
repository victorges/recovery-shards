package model

import (
	"fmt"

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
// The identifier must include a valid checksum byte as its last byte.
// The checksum byte is calculated by XORing all bytes of the identifier (excluding the checksum)
// with all bytes of the mnemonic's entropy.
//
// Returns an error if:
// - The mnemonic is not a valid BIP39 mnemonic
// - The checksum byte in the identifier is invalid
func NewMnemonicShare(identifier string, mnemonic string) (MnemonicShare, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return MnemonicShare{}, fmt.Errorf("invalid mnemonic")
	}
	identifierBytes, err := FromBIP39Word(identifier)
	if err != nil {
		return MnemonicShare{}, fmt.Errorf("invalid identifier: %w", err)
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
	identifier = append(identifier, checksumTribblet(identifier, data))

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
	if expectedChecksum := checksumTribblet(onlyID, entropy); expectedChecksum != checksum {
		return nil, fmt.Errorf("invalid checksum on share %04x (expected: %02x, got: %02x)", s.Identifier, expectedChecksum, checksum)
	}
	return append(entropy, onlyID...), nil
}

// String returns a human-readable string representation of the share.
// The string includes the identifier in hexadecimal and the mnemonic phrase.
func (s MnemonicShare) String() string {
	word, err := ToBIP39Word(s.Identifier)
	if err != nil {
		return fmt.Sprintf("%04x: %s", s.Identifier, s.Mnemonic)
	}
	return fmt.Sprintf("%s (0x%04x): %s", word, s.Identifier, s.Mnemonic)
}

// checksumTribblet calculates a 3-bit checksum by XORing all bytes together,
// then XORing the three resulting 3-bit segments within that byte.
func checksumTribblet(identifier, data []byte) byte {
	// First XOR all bytes together to get a single byte
	var xorByte byte = 0
	for _, b := range append(identifier, data...) {
		xorByte ^= b
	}

	// Then XOR the three 3-bit segments within that byte
	lowBits := xorByte & 0x07         // Bits 0-2
	midBits := (xorByte >> 3) & 0x07  // Bits 3-5
	highBits := (xorByte >> 6) & 0x07 // Bits 6-7
	return (highBits ^ midBits ^ lowBits) & 0x07
}

func ToBIP39Word(bits13 []byte) (string, error) {
	if len(bits13) != 2 {
		return "", fmt.Errorf("must provide 2 bytes to represent 13-bit word index")
	}
	wordIdx := (uint16(bits13[0]) << 3) | uint16(bits13[1]&0x07)
	identifier := bip39.GetWordList()[wordIdx]
	return identifier, nil
}

func FromBIP39Word(word string) ([]byte, error) {
	wordIdx, ok := bip39.GetWordIndex(word)
	if !ok {
		return nil, fmt.Errorf("invalid word: %s", word)
	}
	return []byte{byte((wordIdx >> 3) & 0xff), byte(wordIdx & 0x07)}, nil
}
