import os
import sys
import argparse
from mnemonic import Mnemonic
from secretsharing import PlaintextToHexSecretSharer

mnemo = Mnemonic("english")


# Utility functions
def validate_mnemonic(phrase):
    if not mnemo.check(phrase):
        raise ValueError("Invalid mnemonic phrase provided.")


def phrase_to_entropy(phrase):
    validate_mnemonic(phrase)
    return mnemo.to_entropy(phrase)


def entropy_to_phrase(entropy):
    return mnemo.to_mnemonic(entropy)


def prompt_for_phrase(prompt):
    print(prompt)
    words = []
    for i in range(1, 25):
        word = input(f"Word {i}: ").strip()
        words.append(word)
    return " ".join(words)


def prompt_for_shares(count):
    shares = []
    for i in range(count):
        share = prompt_for_phrase(
            f"Enter the 24-word phrase for share {i + 1}, one word at a time:"
        )
        shares.append(share)
    return shares


# Shamir's Secret Sharing wrapper
def split_secret(entropy, n, k):
    hex_secret = entropy.hex()
    shares = PlaintextToHexSecretSharer.split_secret(hex_secret, k, n)
    return shares


def recover_secret(shares):
    return PlaintextToHexSecretSharer.recover_secret(shares)


# CLI functionality
def create_shares(mnemonic, n, k, output_dir):
    entropy = phrase_to_entropy(mnemonic)
    shares = split_secret(entropy, n, k)

    print(f"Generated {n} shares with a {k}-out-of-{n} threshold.")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        for i, share in enumerate(shares):
            file_path = os.path.join(output_dir, f"share_{i + 1}.txt")
            with open(file_path, "w") as f:
                f.write(share)
            print(f"Saved share {i + 1} to {file_path}.")
    else:
        print("Shares:")
        for i, share in enumerate(shares):
            print(f"Share {i + 1}: {share}")


def recover_phrase(shares):
    recovered_entropy_hex = recover_secret(shares)
    recovered_entropy = bytes.fromhex(recovered_entropy_hex)
    mnemonic = entropy_to_phrase(recovered_entropy)
    print("Recovered mnemonic phrase:")
    print(mnemonic)


def main():
    parser = argparse.ArgumentParser(
        description="Shamir's Secret Sharing for BIP-39 recovery phrases."
    )
    subparsers = parser.add_subparsers(dest="command")

    # Command: create
    create_parser = subparsers.add_parser(
        "create", help="Split a recovery phrase into shares."
    )
    create_parser.add_argument(
        "-n", type=int, default=3, help="Total number of shares to create (default: 3)."
    )
    create_parser.add_argument(
        "-k",
        type=int,
        default=2,
        help="Threshold number of shares needed to recover the phrase (default: 2).",
    )
    create_parser.add_argument(
        "-o", "--output", help="Directory to save the shares.", required=False
    )

    # Command: recover
    recover_parser = subparsers.add_parser(
        "recover", help="Recover a recovery phrase from shares."
    )
    recover_parser.add_argument(
        "-c", "--count", type=int, help="Number of shares to input.", required=False
    )
    recover_parser.add_argument(
        "-d",
        "--directory",
        help="Path to a directory containing share files.",
        required=False,
    )

    args = parser.parse_args()

    if args.command == "create":
        try:
            mnemonic = prompt_for_phrase(
                "Enter your 24-word recovery phrase, one word at a time:"
            )
            create_shares(mnemonic, args.n, args.k, args.output)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "recover":
        shares = []

        if args.directory:
            if not os.path.exists(args.directory):
                print(f"Error: Directory {args.directory} does not exist.")
                sys.exit(1)

            for file_name in os.listdir(args.directory):
                file_path = os.path.join(args.directory, file_name)
                with open(file_path, "r") as f:
                    shares.append(f.read().strip())
        elif args.count:
            try:
                shares = prompt_for_shares(args.count)
            except Exception as e:
                print(f"Error: {e}")
                sys.exit(1)
        else:
            print(
                "Error: Either --count or --directory must be provided to recover shares."
            )
            sys.exit(1)

        if len(shares) < 2:
            print("Error: At least two shares are required to recover the mnemonic.")
            sys.exit(1)

        try:
            recover_phrase(shares)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
