# recovery-shards

A tool for splitting BIP-39 recovery phrases into multiple shards using Shamir's Secret Sharing for additional security. This allows you to distribute your cryptocurrency recovery phrase across multiple locations, requiring a minimum threshold of shards to reconstruct the original phrase.

## Features

- Split a BIP-39 mnemonic into multiple shares (n) with a configurable threshold (k)
- Recover the original mnemonic using k-out-of-n shares
- Verify that shares can correctly reconstruct the original mnemonic
- Store shares in files or display them for manual recording

## Installation

### Build from source

```bash
git clone https://github.com/victorges/recovery-shards.git
cd recovery-shards
make build
```

This will create a binary named `shards` in the project directory.

## Usage

### Split a mnemonic into shares

```bash
./shards split -n 5 -k 3 -out shares/
```

This creates 5 shares where any 3 can reconstruct the original mnemonic. The shares will be saved to the `shares/` directory.

Options:
- `-n`: Total number of shares to create (default: 3)
- `-k`: Minimum number of shares needed to recover the phrase (default: 2)
- `-in`: File containing the recovery phrase (if not provided, will prompt for input)
- `-out`: Directory to save the generated shares (if not provided, shares will be displayed in the terminal)

Example with input file:
```bash
./shards split -n 5 -k 3 -in data/in.txt -out shares/
```

Example with manual input:
```bash
./shards split -n 5 -k 3
# You will be prompted to enter your mnemonic phrase
```

### Recover a mnemonic from shares

```bash
./shards recover -in shares/
```

This will reconstruct the original mnemonic from the shares in the `shares/` directory.

Options:
- `-in`: Path to a directory containing share files
- `-shares`: Number of shares to input manually (if not using files)

Example with manual input:
```bash
./shards recover -shares 3
# You will be prompted to enter 3 shares
```

## Share Format

Each share is stored as a BIP-39 mnemonic with an identifier prefix. The format is:

```
XXXX: word1 word2 word3 ... word24
```

Where `XXXX` is a hexadecimal identifier for the share.

Example:
```
bd13: memory flee chat rigid alpha put morning regular junk into include romance inner island security vivid little clump sport summer jump upgrade once notable
```

## Security Considerations

- Store each share in a different secure location
- The threshold (k) should be high enough that an attacker cannot easily gather enough shares
- The total number of shares (n) should be high enough to provide redundancy if some shares are lost
- Consider using physical media (paper, metal) for long-term storage of shares
- Test the recovery process before relying on it for critical assets

## Example Workflow

1. Split your existing mnemonic into 5 shares, requiring at least 3 to recover:
   ```bash
   ./shards split -n 5 -k 3 -out shares/
   ```

2. Store each share in a secure location. Make sure to save both the mnemonic but also the identifier of each share.

3. Distribute the shares to different secure locations.

4. When needed, recover the original mnemonic using at least 3 shares:
   ```bash
   ./shards recover -in shares/
   ```

## How It Works

This tool implements Shamir's Secret Sharing, a cryptographic algorithm that divides a secret into multiple parts. The original secret can only be reconstructed when a sufficient number of shares (the threshold) are combined.

1. The BIP-39 mnemonic is converted to its entropy representation
2. The entropy is split into n shares using Shamir's Secret Sharing
3. Each share is converted back to a BIP-39 mnemonic format for easier storage
4. To recover, the shares are converted back to entropy, combined, and then converted to the original mnemonic

## License

MIT
