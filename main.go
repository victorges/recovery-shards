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
		wordLen := len(words[0])
		if words[0][wordLen-1] != ':' {
			return nil, "", fmt.Errorf("invalid identifier format must be 2 hex bytes followed by a colon")
		}
		var err error
		identifier, err = hex.DecodeString(words[0][:wordLen-1])
		if err != nil || len(identifier) != 2 {
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

func readSharesFromFile(filepath string) ([]model.MnemonicShare, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read share file: %w", err)
	}

	shares := make([]model.MnemonicShare, 0)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		identifier, mnemonic, err := readMnemonicLine(line)
		if err != nil {
			return nil, fmt.Errorf("invalid mnemonic line: %w", err)
		}
		if identifier == nil {
			return nil, fmt.Errorf("share file must contain identifiers")
		}

		share, err := model.NewMnemonicShare(identifier, mnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to create mnemonic share: %w", err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func readSharesFromDirectory(directory string) ([]model.MnemonicShare, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	allShares := make([]model.MnemonicShare, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		shares, err := readSharesFromFile(filepath.Join(directory, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", file.Name(), err)
		}
		allShares = append(allShares, shares...)
	}
	return allShares, nil
}

func readSharesFromPath(path string) ([]model.MnemonicShare, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read path: %w", err)
	}

	if fileInfo.IsDir() {
		return readSharesFromDirectory(path)
	}
	return readSharesFromFile(path)
}

func writeShares(shares []model.MnemonicShare, outputPath string) error {
	// Check if path ends with slash or is an existing directory
	isDir := strings.HasSuffix(outputPath, "/") || strings.HasSuffix(outputPath, "\\")
	if !isDir {
		if info, err := os.Stat(outputPath); err == nil {
			isDir = info.IsDir()
		}
	}

	if isDir {
		// Ensure directory exists
		dirPath := strings.TrimRight(outputPath, "/\\")
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Write individual files
		for i, share := range shares {
			filename := filepath.Join(dirPath, fmt.Sprintf("share_%02x.txt", share.Identifier))
			content := fmt.Sprintf("%02x: %s", share.Identifier, share.Mnemonic)

			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write share file: %w", err)
			}
			fmt.Printf("Saved share %d to %s\n", i+1, filename)
		}
	} else {
		// Write single file with all shares
		var content strings.Builder
		for _, share := range shares {
			fmt.Fprintf(&content, "%02x: %s\n", share.Identifier, share.Mnemonic)
		}

		if err := os.WriteFile(outputPath, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("failed to write shares file: %w", err)
		}
		fmt.Printf("Saved %d shares to %s\n", len(shares), outputPath)
	}
	return nil
}

func printShares(shares []model.MnemonicShare) {
	fmt.Println("Shares:")
	for _, share := range shares {
		fmt.Printf("%02x: %s\n", share.Identifier, share.Mnemonic)
	}
}

func RunCLI(args []string) error {
	splitCmd := flag.NewFlagSet("split", flag.ExitOnError)
	splitTotal := splitCmd.Int("n", 3, "Total number of shares to create (default: 3)")
	splitThreshold := splitCmd.Int("k", 2, "Minimum number of shares needed to recover the phrase (default: 2)")
	splitInputFile := splitCmd.String("in", "", "File containing the recovery phrase (if not provided, will prompt for input)")
	splitOutputDir := splitCmd.String("out", "", "Directory to save the generated shares")

	recoverCmd := flag.NewFlagSet("recover", flag.ExitOnError)
	recoverShareCount := recoverCmd.Int("shares", 0, "Number of shares to input manually")
	recoverInputDir := recoverCmd.String("in", "", "Path to a directory containing share files")

	if len(args) < 2 {
		return fmt.Errorf("expected 'split' or 'recover' subcommand")
	}

	switch args[1] {
	case "generate":
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		fmt.Println("Generated mnemonic:")
		fmt.Printf("\n%s\n", mnemonic)

	case "split":
		splitCmd.Parse(args[2:])
		var mnemonic string
		var err error

		if *splitInputFile != "" {
			var identifier []byte
			identifier, mnemonic, err = readMnemonicFromFile(*splitInputFile)
			if err != nil {
				return fmt.Errorf("error reading input file: %v", err)
			} else if identifier != nil {
				return fmt.Errorf("unexpected identifier in input file: %02x", identifier)
			}
		} else {
			mnemonic, err = promptForPhrase("Enter your 24-word recovery phrase, one word at a time:")
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}
		}

		shares, err := command.Split(mnemonic, *splitTotal, *splitThreshold)
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if err := command.VerifyShares(mnemonic, shares, *splitThreshold); err != nil {
			return fmt.Errorf("error verifying shares: %v", err)
		}

		fmt.Printf("Generated %d shares with a %d-out-of-%d threshold.\n", *splitTotal, *splitThreshold, *splitTotal)

		if *splitOutputDir != "" {
			if err := writeShares(shares, *splitOutputDir); err != nil {
				return fmt.Errorf("error: %v", err)
			}
		}
		printShares(shares)

	case "recover":
		recoverCmd.Parse(args[2:])
		var shares []model.MnemonicShare
		var err error

		if *recoverInputDir != "" {
			shares, err = readSharesFromPath(*recoverInputDir)
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}
		} else if *recoverShareCount > 0 {
			shares, err = promptForShares(*recoverShareCount)
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}
		} else {
			return fmt.Errorf("either --shares or --in must be provided to recover shares")
		}

		if len(shares) < 2 {
			return fmt.Errorf("at least two shares are required to recover the mnemonic")
		}

		mnemonic, err := command.Recover(shares)
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		fmt.Println("Recovered mnemonic phrase:")
		fmt.Printf("\n%s\n", mnemonic)

	default:
		return fmt.Errorf("unknown command: %s", args[1])
	}

	return nil
}

func main() {
	if err := RunCLI(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
