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
	"github.com/victorges/recovery-shards/model"
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

func promptForShares(count int) ([]model.MnemonicShare, error) {
	shares := make([]model.MnemonicShare, 0, count)
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
		mnemonic := strings.TrimSpace(reader.Text())

		share, err := model.NewMnemonicShare(identifier, mnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to create mnemonic share: %w", err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func readMnemonicLine(content string) ([]byte, string, error) {
	words := strings.Fields(content)
	identifier := []byte(nil)
	if len(words) == 25 {
		if len(words[0]) != 3 || words[0][2] != ':' {
			return nil, "", fmt.Errorf("invalid identifier format must be a hex byte followed by a colon")
		}
		var err error
		identifier, err = hex.DecodeString(words[0][:2])
		if err != nil {
			return nil, "", fmt.Errorf("invalid identifier hex code: %w", err)
		}
		words = words[1:]
	} else if len(words) != 24 {
		return nil, "", fmt.Errorf("mnemonic must contain exactly 24 words")
	}

	for _, word := range words {
		if _, ok := bip39.GetWordIndex(word); !ok {
			return nil, "", fmt.Errorf("invalid word in mnemonic: %s", word)
		}
	}

	return identifier, strings.Join(words, " "), nil
}

func readMnemonicFromFile(filepath string) ([]byte, string, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read mnemonic file: %w", err)
	}

	return readMnemonicLine(string(content))
}

func readSharesFromDirectory(directory string) ([]model.MnemonicShare, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	shares := make([]model.MnemonicShare, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		content, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read share file: %w", err)
		}

		identifier, mnemonic, err := readMnemonicLine(string(content))
		if err != nil {
			return nil, fmt.Errorf("invalid mnemonic in file: %w", err)
		}

		share, err := model.NewMnemonicShare(identifier, mnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to create mnemonic share: %w", err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func writeShares(shares []model.MnemonicShare, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for i, share := range shares {
		filename := filepath.Join(outputDir, fmt.Sprintf("share_%02x.txt", share.Identifier))
		content := fmt.Sprintf("%02x: %s", share.Identifier, share.Mnemonic)

		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write share file: %w", err)
		}
		fmt.Printf("Saved share %d to %s\n", i+1, filename)
	}
	return nil
}

func printShares(shares []model.MnemonicShare) {
	fmt.Println("Shares:")
	for i, share := range shares {
		fmt.Printf("Share %d: %02x: %s\n", i+1, share.Identifier, share.Mnemonic)
	}
}

func main() {
	splitCmd := flag.NewFlagSet("split", flag.ExitOnError)
	splitTotal := splitCmd.Int("n", 3, "Total number of shares to create (default: 3)")
	splitThreshold := splitCmd.Int("k", 2, "Minimum number of shares needed to recover the phrase (default: 2)")
	splitInputFile := splitCmd.String("in", "", "File containing the recovery phrase (if not provided, will prompt for input)")
	splitOutputDir := splitCmd.String("out", "", "Directory to save the generated shares")

	recoverCmd := flag.NewFlagSet("recover", flag.ExitOnError)
	recoverShareCount := recoverCmd.Int("shares", 0, "Number of shares to input manually")
	recoverInputDir := recoverCmd.String("in", "", "Path to a directory containing share files")

	if len(os.Args) < 2 {
		fmt.Println("Expected 'split' or 'recover' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

		fmt.Println("Generated mnemonic:")
		fmt.Printf("\n%s\n", mnemonic)
	case "split":
		splitCmd.Parse(os.Args[2:])
		var mnemonic string
		var err error

		if *splitInputFile != "" {
			var identifier []byte
			identifier, mnemonic, err = readMnemonicFromFile(*splitInputFile)
			if err != nil {
				fmt.Printf("Error reading input file: %v\n", err)
				os.Exit(1)
			} else if identifier != nil {
				fmt.Printf("Unexpected identifier in input file: %02x\n", identifier)
				os.Exit(1)
			}
		} else {
			mnemonic, err = promptForPhrase("Enter your 24-word recovery phrase, one word at a time:")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		}

		shares, err := command.Split(mnemonic, *splitTotal, *splitThreshold)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if err := command.VerifyShares(mnemonic, shares, *splitThreshold); err != nil {
			fmt.Printf("Error verifying shares: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Generated %d shares with a %d-out-of-%d threshold.\n", *splitTotal, *splitThreshold, *splitTotal)

		if *splitOutputDir != "" {
			if err := writeShares(shares, *splitOutputDir); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			printShares(shares)
		}

	case "recover":
		recoverCmd.Parse(os.Args[2:])
		var shares []model.MnemonicShare
		var err error

		if *recoverInputDir != "" {
			shares, err = readSharesFromDirectory(*recoverInputDir)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else if *recoverShareCount > 0 {
			shares, err = promptForShares(*recoverShareCount)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Error: Either --shares or --in must be provided to recover shares")
			os.Exit(1)
		}

		if len(shares) < 2 {
			fmt.Println("Error: At least two shares are required to recover the mnemonic")
			os.Exit(1)
		}

		mnemonic, err := command.Recover(shares)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Recovered mnemonic phrase:")
		fmt.Printf("\n%s\n", mnemonic)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
