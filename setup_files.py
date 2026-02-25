#!/usr/bin/env python3
"""
Download test files from Pat Meenan's shared-brotli-test repo.
These files (dictionary.js and bundle.js) are similar minified JavaScript bundles
that share significant content, making them ideal for demonstrating dictionary
compression gains.
"""

import os
import requests
import hashlib

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Test files from https://github.com/pmeenan/shared-brotli-test
FILES = {
    "dictionary.js": "https://raw.githubusercontent.com/pmeenan/shared-brotli-test/main/dictionary.js",
    "bundle.js": "https://raw.githubusercontent.com/pmeenan/shared-brotli-test/main/bundle.js",
    # Pre-compressed files for serving without runtime compression
    "bundle.js.br": "https://raw.githubusercontent.com/pmeenan/shared-brotli-test/main/bundle.js.br",
    "bundle.js.gz": "https://raw.githubusercontent.com/pmeenan/shared-brotli-test/main/bundle.js.gz",
    # Dictionary-compressed brotli (.sbr) - note the long filename in the repo includes hash
    "bundle.js.sbr": "https://raw.githubusercontent.com/pmeenan/shared-brotli-test/main/bundle.js.sbr.74b856e554018fec0d6054c51bc1588fbf2386338d851842447a9510db015732",
}


def download_file(name: str, url: str) -> bool:
    """Download a file from URL to static directory."""
    filepath = os.path.join(STATIC_DIR, name)

    print(f"Downloading {name}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        with open(filepath, "wb") as f:
            f.write(response.content)

        # Calculate SHA-256 hash
        hash_hex = hashlib.sha256(response.content).hexdigest()
        print(f"  -> Saved to {filepath}")
        print(f"  -> Size: {len(response.content):,} bytes")
        print(f"  -> SHA-256: {hash_hex}")
        return True

    except requests.RequestException as e:
        print(f"  -> ERROR: Failed to download {name}: {e}")
        return False


def main():
    """Download all test files."""
    os.makedirs(STATIC_DIR, exist_ok=True)

    print("=" * 60)
    print("Downloading test files for shared dictionary compression")
    print("=" * 60)
    print()

    success = True
    for name, url in FILES.items():
        if not download_file(name, url):
            success = False
        print()

    if success:
        print("=" * 60)
        print("All files downloaded successfully!")
        print("You can now run the server with: python app.py")
        print("=" * 60)
    else:
        print("=" * 60)
        print("Some files failed to download. Please check the errors above.")
        print("=" * 60)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
