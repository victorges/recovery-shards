package model

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

type MnemonicShare struct {
	Identifier []byte
	Mnemonic   string
}

func NewMnemonicShare(identifier []byte, mnemonic string) (MnemonicShare, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return MnemonicShare{}, fmt.Errorf("invalid mnemonic")
	}
	share := MnemonicShare{
		Identifier: identifier,
		Mnemonic:   mnemonic,
	}
	// check the check byte
	if _, err := share.ToShamir(); err != nil {
		return MnemonicShare{}, fmt.Errorf("invalid share: %w", err)
	}
	return share, nil
}

func NewMnemonicShareFromShamir(share []byte) (MnemonicShare, error) {
	if len(share) < 2 {
		return MnemonicShare{}, fmt.Errorf("invalid share length")
	}
	data := share[:len(share)-shamir.ShareOverhead]
	identifier := share[len(share)-shamir.ShareOverhead:]
	identifier = append(identifier, xorCheckByte(identifier, data))

	shareMnemonic, err := bip39.NewMnemonic(data)
	if err != nil {
		return MnemonicShare{}, fmt.Errorf("failed to generate mnemonic for share: %w", err)
	}
	return MnemonicShare{
		Identifier: identifier,
		Mnemonic:   shareMnemonic,
	}, nil
}

func (s MnemonicShare) ToShamir() ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(s.Mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	checkByte := s.Identifier[len(s.Identifier)-1]
	onlyID := s.Identifier[:len(s.Identifier)-1]
	if xorCheckByte(onlyID, entropy) != checkByte {
		return nil, fmt.Errorf("invalid check byte on share %02x", s.Identifier)
	}
	return append(entropy, onlyID...), nil
}

func xorCheckByte(identifier, data []byte) byte {
	checkByte := byte(0)
	for _, b := range append(identifier, data...) {
		checkByte ^= b
	}
	return checkByte
}
