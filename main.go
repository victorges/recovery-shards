package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"github.com/victorges/recovery-shards/command"
)

func promptForPhrase(prompt string) (string, error) {
	fmt.Println(prompt)
	words := make([]string, 0, 24)
	reader := bufio.NewScanner(os.Stdin)

	for i := 0; i < 24; {
		fmt.Printf("Word %d: ", i)
		if !reader.Scan() {
			return "", fmt.Errorf("failed to read input")
		}

		word := strings.TrimSpace(strings.ToLower(reader.Text()))
		if _, ok := bip39.GetWordIndex(word); !ok {
			fmt.Printf("Invalid word: %s\n", word)
			continue
		}

		words = append(words, word)
		i++
	}

	return strings.Join(words, " "), nil
}

func promptForShares(count int) ([]command.ShareInfo, error) {
	shares := make([]command.ShareInfo, 0, count)
	for i := 0; i < count; i++ {
		fmt.Printf("\nShare %d:\n", i+1)
		fmt.Print("Identifier (hex): ")

		var identifierHex string
		if _, err := fmt.Scanln(&identifierHex); err != nil {
			return nil, fmt.Errorf("failed to read identifier: %w", err)
		}

		identifier, err := hex.DecodeString(identifierHex)
		if err != nil || len(identifier) != 1 {
			return nil, fmt.Errorf("invalid identifier format")
		}

		fmt.Println("Enter the mnemonic phrase for this share:")
		reader := bufio.NewScanner(os.Stdin)
		if !reader.Scan() {
			return nil, fmt.Errorf("failed to read mnemonic")
		}
		shareMnemonic := strings.TrimSpace(reader.Text())

		if !bip39.IsMnemonicValid(shareMnemonic) {
			return nil, fmt.Errorf("invalid mnemonic phrase")
		}

		entropy, err := bip39.EntropyFromMnemonic(shareMnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to process mnemonic: %w", err)
		}

		shares = append(shares, command.ShareInfo{
			Identifier: identifier[0],
			Data:       entropy,
		})
	}
	return shares, nil
}

func readSharesFromDirectory(directory string) ([]command.ShareInfo, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	shares := make([]command.ShareInfo, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		content, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read share file: %w", err)
		}

		lines := strings.Split(string(content), "\n")
		if len(lines) != 2 {
			return nil, fmt.Errorf("invalid share file format")
		}

		var identifierHex string
		fmt.Sscanf(lines[0], "Identifier: %s", &identifierHex)

		var shareMnemonic string
		fmt.Sscanf(lines[1], "Mnemonic: %s", &shareMnemonic)
		shareMnemonic = strings.TrimPrefix(lines[1], "Mnemonic: ")

		identifier, err := hex.DecodeString(identifierHex)
		if err != nil || len(identifier) != 1 {
			return nil, fmt.Errorf("invalid identifier format in file")
		}

		if !bip39.IsMnemonicValid(shareMnemonic) {
			return nil, fmt.Errorf("invalid mnemonic in file")
		}

		entropy, err := bip39.EntropyFromMnemonic(shareMnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to process mnemonic: %w", err)
		}

		shares = append(shares, command.ShareInfo{
			Identifier: identifier[0],
			Data:       entropy,
		})
	}
	return shares, nil
}

func main() {
	splitCmd := flag.NewFlagSet("split", flag.ExitOnError)
	splitN := splitCmd.Int("n", 3, "Total number of shares to create (default: 3)")
	splitK := splitCmd.Int("k", 2, "Threshold number of shares needed to recover the phrase (default: 2)")
	splitOutput := splitCmd.String("o", "", "Directory to save the shares")

	recoverCmd := flag.NewFlagSet("recover", flag.ExitOnError)
	recoverCount := recoverCmd.Int("c", 0, "Number of shares to input")
	recoverDir := recoverCmd.String("d", "", "Path to a directory containing share files")

	if len(os.Args) < 2 {
		fmt.Println("Expected 'split' or 'recover' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "split":
		splitCmd.Parse(os.Args[2:])
		mnemonic, err := promptForPhrase("Enter your 24-word recovery phrase, one word at a time:")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if err := command.Split(mnemonic, *splitN, *splitK, *splitOutput); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "recover":
		recoverCmd.Parse(os.Args[2:])
		var shares []command.ShareInfo
		var err error

		if *recoverDir != "" {
			shares, err = readSharesFromDirectory(*recoverDir)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else if *recoverCount > 0 {
			shares, err = promptForShares(*recoverCount)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Error: Either --count or --directory must be provided to recover shares")
			os.Exit(1)
		}

		if len(shares) < 2 {
			fmt.Println("Error: At least two shares are required to recover the mnemonic")
			os.Exit(1)
		}

		if err := command.Recover(shares); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
