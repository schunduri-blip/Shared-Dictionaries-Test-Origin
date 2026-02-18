#!/usr/bin/env python3
"""
Validation Script for Shared Dictionary Test Origin

This script validates that the test origin server is correctly implementing
RFC 9842 shared dictionary compression by:

1. Fetching the dictionary and verifying Use-As-Dictionary header
2. Fetching bundle with dcb encoding and verifying it can be decompressed
3. Fetching bundle with dcz encoding and verifying it can be decompressed
4. Verifying the decompressed content matches the original
5. Testing fallback behavior when dictionary doesn't match

Usage:
    python validate.py [--url http://localhost:8080]
"""

import argparse
import hashlib
import base64
import sys
import requests
import zstandard as zstd


# DCB/DCZ magic headers per RFC 9842
DCB_MAGIC = b"\xff\x44\x43\x42"  # 4 bytes
DCZ_MAGIC = b"\x5e\x2a\x4d\x18\x20\x00\x00\x00"  # 8 bytes
SHA256_LENGTH = 32  # bytes


class ValidationError(Exception):
    """Raised when a validation check fails."""
    pass


class TestResult:
    """Holds the result of a single test."""
    def __init__(self, name: str, passed: bool, message: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
    
    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        msg = f" - {self.message}" if self.message else ""
        return f"[{status}] {self.name}{msg}"


def decompress_dcb(data: bytes, dictionary: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Decompress dcb (dictionary-compressed brotli) data.
    
    Returns: (magic, embedded_hash, decompressed_content)
    """
    import subprocess
    import tempfile
    import os
    
    # Parse header
    if len(data) < len(DCB_MAGIC) + SHA256_LENGTH:
        raise ValidationError(f"DCB data too short: {len(data)} bytes")
    
    magic = data[:len(DCB_MAGIC)]
    if magic != DCB_MAGIC:
        raise ValidationError(f"Invalid DCB magic: {magic.hex()} (expected {DCB_MAGIC.hex()})")
    
    embedded_hash = data[len(DCB_MAGIC):len(DCB_MAGIC) + SHA256_LENGTH]
    compressed = data[len(DCB_MAGIC) + SHA256_LENGTH:]
    
    # Decompress using brotli CLI with dictionary
    with tempfile.NamedTemporaryFile(delete=False, suffix=".dict") as dict_file:
        dict_file.write(dictionary)
        dict_path = dict_file.name
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".br") as compressed_file:
        compressed_file.write(compressed)
        compressed_path = compressed_file.name
    
    try:
        result = subprocess.run(
            ["brotli", "-d", "--stdout", "-D", dict_path, compressed_path],
            capture_output=True,
            check=True
        )
        decompressed = result.stdout
    except subprocess.CalledProcessError as e:
        raise ValidationError(f"Brotli decompression failed: {e.stderr.decode()}")
    except FileNotFoundError:
        raise ValidationError("brotli CLI not found. Install with: brew install brotli")
    finally:
        os.unlink(dict_path)
        os.unlink(compressed_path)
    
    return magic, embedded_hash, decompressed


def decompress_dcz(data: bytes, dictionary: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Decompress dcz (dictionary-compressed zstd) data.
    
    Returns: (magic, embedded_hash, decompressed_content)
    """
    # Parse header
    if len(data) < len(DCZ_MAGIC) + SHA256_LENGTH:
        raise ValidationError(f"DCZ data too short: {len(data)} bytes")
    
    magic = data[:len(DCZ_MAGIC)]
    if magic != DCZ_MAGIC:
        raise ValidationError(f"Invalid DCZ magic: {magic.hex()} (expected {DCZ_MAGIC.hex()})")
    
    embedded_hash = data[len(DCZ_MAGIC):len(DCZ_MAGIC) + SHA256_LENGTH]
    compressed = data[len(DCZ_MAGIC) + SHA256_LENGTH:]
    
    # Decompress using zstandard library with dictionary
    try:
        zstd_dict = zstd.ZstdCompressionDict(dictionary)
        dctx = zstd.ZstdDecompressor(dict_data=zstd_dict)
        decompressed = dctx.decompress(compressed)
    except zstd.ZstdError as e:
        raise ValidationError(f"Zstd decompression failed: {e}")
    
    return magic, embedded_hash, decompressed


def test_dictionary_response(base_url: str) -> tuple[TestResult, bytes, str, str]:
    """
    Test 1: Fetch dictionary and verify Use-As-Dictionary header.
    
    Returns: (result, dictionary_content, dict_hash_b64, dict_id)
    """
    url = f"{base_url}/dictionary.js"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("Dictionary fetch", False, str(e)), None, None, None
    
    # Check Use-As-Dictionary header
    use_as_dict = response.headers.get("Use-As-Dictionary")
    if not use_as_dict:
        return TestResult("Dictionary fetch", False, "Missing Use-As-Dictionary header"), None, None, None
    
    # Parse the header to extract id, match, match-dest
    # Format: id="dict-v1", match="/bundle.js", match-dest=("script")
    if 'id="' not in use_as_dict or 'match="' not in use_as_dict:
        return TestResult("Dictionary fetch", False, f"Invalid Use-As-Dictionary format: {use_as_dict}"), None, None, None
    
    # Extract dictionary ID from header
    try:
        id_start = use_as_dict.index('id="') + 4
        id_end = use_as_dict.index('"', id_start)
        dict_id = use_as_dict[id_start:id_end]
    except ValueError:
        return TestResult("Dictionary fetch", False, "Could not parse dictionary ID"), None, None, None
    
    # Get dictionary content and compute hash
    dictionary = response.content
    dict_hash = hashlib.sha256(dictionary).digest()
    dict_hash_b64 = base64.b64encode(dict_hash).decode("ascii")
    
    # Verify X-Dictionary-Hash header matches our computed hash
    x_dict_hash = response.headers.get("X-Dictionary-Hash")
    if x_dict_hash and x_dict_hash != dict_hash.hex():
        return TestResult("Dictionary fetch", False, f"Hash mismatch: server={x_dict_hash}, computed={dict_hash.hex()}"), None, None, None
    
    msg = f"Use-As-Dictionary: {use_as_dict[:60]}..."
    return TestResult("Dictionary fetch", True, msg), dictionary, dict_hash_b64, dict_id


def test_dcb_compression(base_url: str, dictionary: bytes, dict_hash_b64: str, dict_id: str) -> TestResult:
    """
    Test 2: Fetch bundle with dcb encoding and verify decompression.
    """
    url = f"{base_url}/bundle.js"
    headers = {
        "Accept-Encoding": "dcb, br, gzip",
        "Available-Dictionary": f":{dict_hash_b64}:",
        "Dictionary-ID": f'"{dict_id}"',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("DCB compression", False, str(e))
    
    # Check Content-Encoding
    content_encoding = response.headers.get("Content-Encoding")
    if content_encoding != "dcb":
        x_type = response.headers.get("X-Compression-Type", "unknown")
        return TestResult("DCB compression", False, f"Expected dcb, got {content_encoding} (X-Compression-Type: {x_type})")
    
    # Decompress and verify
    try:
        magic, embedded_hash, decompressed = decompress_dcb(response.content, dictionary)
    except ValidationError as e:
        return TestResult("DCB compression", False, str(e))
    
    # Verify embedded hash matches dictionary hash
    expected_hash = hashlib.sha256(dictionary).digest()
    if embedded_hash != expected_hash:
        return TestResult("DCB compression", False, f"Embedded hash mismatch")
    
    # Verify decompressed size matches X-Original-Size
    x_original_size = response.headers.get("X-Original-Size")
    if x_original_size and len(decompressed) != int(x_original_size):
        return TestResult("DCB compression", False, f"Size mismatch: decompressed={len(decompressed)}, expected={x_original_size}")
    
    x_compressed = response.headers.get("X-Compressed-Size")
    ratio = len(response.content) / len(decompressed) * 100
    return TestResult("DCB compression", True, f"Decompressed {len(response.content)} -> {len(decompressed)} bytes ({ratio:.2f}%)")


def test_dcz_compression(base_url: str, dictionary: bytes, dict_hash_b64: str, dict_id: str) -> TestResult:
    """
    Test 3: Fetch bundle with dcz encoding and verify decompression.
    """
    url = f"{base_url}/bundle.js"
    headers = {
        "Accept-Encoding": "dcz, br, gzip",
        "Available-Dictionary": f":{dict_hash_b64}:",
        "Dictionary-ID": f'"{dict_id}"',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("DCZ compression", False, str(e))
    
    # Check Content-Encoding
    content_encoding = response.headers.get("Content-Encoding")
    if content_encoding != "dcz":
        x_type = response.headers.get("X-Compression-Type", "unknown")
        return TestResult("DCZ compression", False, f"Expected dcz, got {content_encoding} (X-Compression-Type: {x_type})")
    
    # Decompress and verify
    try:
        magic, embedded_hash, decompressed = decompress_dcz(response.content, dictionary)
    except ValidationError as e:
        return TestResult("DCZ compression", False, str(e))
    
    # Verify embedded hash matches dictionary hash
    expected_hash = hashlib.sha256(dictionary).digest()
    if embedded_hash != expected_hash:
        return TestResult("DCZ compression", False, f"Embedded hash mismatch")
    
    # Verify decompressed size matches X-Original-Size
    x_original_size = response.headers.get("X-Original-Size")
    if x_original_size and len(decompressed) != int(x_original_size):
        return TestResult("DCZ compression", False, f"Size mismatch: decompressed={len(decompressed)}, expected={x_original_size}")
    
    ratio = len(response.content) / len(decompressed) * 100
    return TestResult("DCZ compression", True, f"Decompressed {len(response.content)} -> {len(decompressed)} bytes ({ratio:.2f}%)")


def test_content_integrity(base_url: str, dictionary: bytes, dict_hash_b64: str, dict_id: str) -> TestResult:
    """
    Test 4: Verify decompressed dcb/dcz content matches uncompressed bundle.
    """
    url = f"{base_url}/bundle.js"
    
    # Get uncompressed bundle
    try:
        response_plain = requests.get(url, headers={"Accept-Encoding": "identity"}, timeout=10)
        response_plain.raise_for_status()
        original_content = response_plain.content
    except requests.RequestException as e:
        return TestResult("Content integrity", False, f"Failed to fetch uncompressed: {e}")
    
    # Get DCZ compressed and decompress
    headers = {
        "Accept-Encoding": "dcz",
        "Available-Dictionary": f":{dict_hash_b64}:",
        "Dictionary-ID": f'"{dict_id}"',
    }
    try:
        response_dcz = requests.get(url, headers=headers, timeout=30)
        response_dcz.raise_for_status()
        _, _, decompressed_dcz = decompress_dcz(response_dcz.content, dictionary)
    except (requests.RequestException, ValidationError) as e:
        return TestResult("Content integrity", False, f"DCZ decompression failed: {e}")
    
    # Compare
    if original_content != decompressed_dcz:
        return TestResult("Content integrity", False, f"Content mismatch: original={len(original_content)}, decompressed={len(decompressed_dcz)}")
    
    # Also verify hash
    original_hash = hashlib.sha256(original_content).hexdigest()[:16]
    decompressed_hash = hashlib.sha256(decompressed_dcz).hexdigest()[:16]
    
    return TestResult("Content integrity", True, f"SHA256 match: {original_hash}...")


def test_fallback_wrong_hash(base_url: str, dict_id: str) -> TestResult:
    """
    Test 5: Verify server falls back to standard compression when dictionary hash is wrong.
    """
    url = f"{base_url}/bundle.js"
    wrong_hash = base64.b64encode(b"\x00" * 32).decode("ascii")
    headers = {
        "Accept-Encoding": "dcb, br, gzip",
        "Available-Dictionary": f":{wrong_hash}:",
        "Dictionary-ID": f'"{dict_id}"',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("Fallback (wrong hash)", False, str(e))
    
    content_encoding = response.headers.get("Content-Encoding")
    x_hash_match = response.headers.get("X-Dictionary-Hash-Match")
    
    if content_encoding in ("dcb", "dcz"):
        return TestResult("Fallback (wrong hash)", False, f"Should not use dictionary compression, got {content_encoding}")
    
    if x_hash_match != "false":
        return TestResult("Fallback (wrong hash)", False, f"X-Dictionary-Hash-Match should be false, got {x_hash_match}")
    
    return TestResult("Fallback (wrong hash)", True, f"Correctly fell back to {content_encoding}")


def test_fallback_wrong_id(base_url: str, dict_hash_b64: str) -> TestResult:
    """
    Test 6: Verify server falls back to standard compression when dictionary ID is wrong.
    """
    url = f"{base_url}/bundle.js"
    headers = {
        "Accept-Encoding": "dcb, br, gzip",
        "Available-Dictionary": f":{dict_hash_b64}:",
        "Dictionary-ID": '"wrong-id"',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("Fallback (wrong ID)", False, str(e))
    
    content_encoding = response.headers.get("Content-Encoding")
    x_id_match = response.headers.get("X-Dictionary-ID-Match")
    
    if content_encoding in ("dcb", "dcz"):
        return TestResult("Fallback (wrong ID)", False, f"Should not use dictionary compression, got {content_encoding}")
    
    if x_id_match != "false":
        return TestResult("Fallback (wrong ID)", False, f"X-Dictionary-ID-Match should be false, got {x_id_match}")
    
    return TestResult("Fallback (wrong ID)", True, f"Correctly fell back to {content_encoding}")


def test_fallback_no_dictionary_headers(base_url: str) -> TestResult:
    """
    Test 7: Verify server uses standard compression when no dictionary headers are sent.
    """
    url = f"{base_url}/bundle.js"
    headers = {
        "Accept-Encoding": "dcb, dcz, br, gzip",
        # No Available-Dictionary or Dictionary-ID
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        return TestResult("Fallback (no dict headers)", False, str(e))
    
    content_encoding = response.headers.get("Content-Encoding")
    
    if content_encoding in ("dcb", "dcz"):
        return TestResult("Fallback (no dict headers)", False, f"Should not use dictionary compression, got {content_encoding}")
    
    return TestResult("Fallback (no dict headers)", True, f"Correctly used {content_encoding}")


def main():
    parser = argparse.ArgumentParser(description="Validate Shared Dictionary Test Origin")
    parser.add_argument("--url", default="http://localhost:8080", help="Base URL of the test origin")
    args = parser.parse_args()
    
    print("=" * 70)
    print("Shared Dictionary Test Origin - Validation")
    print("=" * 70)
    print(f"Target: {args.url}")
    print("=" * 70)
    print()
    
    results = []
    
    # Test 1: Dictionary response
    print("Running tests...")
    print()
    
    result, dictionary, dict_hash_b64, dict_id = test_dictionary_response(args.url)
    results.append(result)
    print(result)
    
    if not result.passed or dictionary is None:
        print("\nCannot continue without dictionary. Aborting.")
        return 1
    
    print(f"  Dictionary size: {len(dictionary):,} bytes")
    print(f"  Dictionary hash: {dict_hash_b64[:32]}...")
    print(f"  Dictionary ID: {dict_id}")
    print()
    
    # Test 2: DCB compression
    result = test_dcb_compression(args.url, dictionary, dict_hash_b64, dict_id)
    results.append(result)
    print(result)
    
    # Test 3: DCZ compression
    result = test_dcz_compression(args.url, dictionary, dict_hash_b64, dict_id)
    results.append(result)
    print(result)
    
    # Test 4: Content integrity
    result = test_content_integrity(args.url, dictionary, dict_hash_b64, dict_id)
    results.append(result)
    print(result)
    
    # Test 5: Fallback with wrong hash
    result = test_fallback_wrong_hash(args.url, dict_id)
    results.append(result)
    print(result)
    
    # Test 6: Fallback with wrong ID
    result = test_fallback_wrong_id(args.url, dict_hash_b64)
    results.append(result)
    print(result)
    
    # Test 7: Fallback with no dictionary headers
    result = test_fallback_no_dictionary_headers(args.url)
    results.append(result)
    print(result)
    
    # Summary
    print()
    print("=" * 70)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! The test origin is correctly implemented.")
        return 0
    else:
        print("Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
