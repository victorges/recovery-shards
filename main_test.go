package main

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/shamir"
)

func Test_main(t *testing.T) {
	// The secret to be split
	secret := []byte("this is a very secret message")
	fmt.Printf("Secret:\n\tData: %x\n", secret)

	// Split the secret into 5 shares, with a threshold of 3
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		fmt.Println("Error splitting secret:", err)
		return
	}
	fmt.Println()

	// Print the shares with separated identifiers
	fmt.Println("Shares:")
	for i, share := range shares {
		identifier, data := splitShare(share)
		fmt.Printf("Share %d:\n\tIdentifier: %02x\n\tData: %x\n", i+1, identifier, data)
	}

	// Recover the secret using any 3 of the shares
	recovered, err := shamir.Combine(shares[:3])
	if err != nil {
		fmt.Println("Error recovering secret:", err)
		return
	}

	// Print the recovered secret
	fmt.Println("Recovered Secret:", string(recovered))
}

func splitShare(share []byte) (byte, []byte) {
	if len(share) < 2 {
		panic("invalid share length")
	}
	data := share[:len(share)-shamir.ShareOverhead]
	identifier := share[len(share)-shamir.ShareOverhead]
	return identifier, data
}
