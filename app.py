#!/usr/bin/env python3
"""
Shared Dictionary Test Origin Server

A Flask server for testing RFC 9842 shared dictionary compression passthrough.
This server serves PRE-COMPRESSED files from Pat Meenan's shared-brotli-test repo
for testing pingora-origin's passthrough support.

Pre-compressed files (in static/):
    bundle.js       - 278,518 bytes (uncompressed)
    bundle.js.sbr   - 1,976 bytes   (dictionary-compressed brotli, 99.3% reduction!)
    bundle.js.br    - 82,312 bytes  (standard brotli)
    bundle.js.gz    - 94,843 bytes  (gzip)

Usage:
    python app.py [--port PORT] [--host HOST]

Endpoints:
    GET /dictionary.js  - Returns dictionary file with Use-As-Dictionary header
    GET /bundle.js      - Returns pre-compressed content based on Accept-Encoding
    GET /health         - Health check endpoint
    GET /              - Info page with test instructions

Headers:
    Request:
        Accept-Encoding: br, dcb, gzip, identity
        Available-Dictionary: :<base64-sha256>:

    Response:
        Content-Encoding: dcb | br | gzip | identity
        Vary: Accept-Encoding, Available-Dictionary
        Use-As-Dictionary: match="/bundle.js" (on dictionary response)
        X-Original-Size: <size in bytes>
        X-Compressed-Size: <size in bytes>
        X-Compression-Ratio: <ratio>
        X-Compression-Type: dcb | br | gzip | identity
        X-Serving-Mode: pre-compressed
"""

import os
import hashlib
import base64
import time
import logging
from functools import lru_cache
from flask import Flask, request, Response, jsonify, render_template

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


def log_request(endpoint: str, compression_used: str = None, extra_info: dict = None):
    """Log incoming request with relevant headers and response info."""
    client_ip = request.remote_addr
    method = request.method

    # Key headers for dictionary compression
    accept_encoding = request.headers.get("Accept-Encoding", "-")
    available_dict = request.headers.get("Available-Dictionary", "-")
    dict_id = request.headers.get("Dictionary-ID", "-")
    user_agent = request.headers.get("User-Agent", "-")

    # Truncate user agent for readability
    if len(user_agent) > 50:
        user_agent = user_agent[:50] + "..."

    log_parts = [
        f"[{endpoint}]",
        f"IP={client_ip}",
        f"Accept-Encoding={accept_encoding}",
    ]

    # Only log dictionary headers if present (not "-")
    if available_dict != "-":
        # Truncate the hash for readability
        if len(available_dict) > 20:
            available_dict = available_dict[:20] + "..."
        log_parts.append(f"Available-Dictionary={available_dict}")

    if dict_id != "-":
        log_parts.append(f"Dictionary-ID={dict_id}")

    if compression_used:
        log_parts.append(f"-> Response={compression_used}")

    if extra_info:
        for key, value in extra_info.items():
            log_parts.append(f"{key}={value}")

    logger.info(" | ".join(log_parts))


# Configuration
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
DICTIONARY_FILE = "dictionary.js"
BUNDLE_FILE = "bundle.js"


# The dictionary ID is used by clients to identify which dictionary they have
# This should be a unique identifier for the dictionary
DICTIONARY_ID = "dict-v1"
# Match pattern for Use-As-Dictionary header - which URLs can use this dictionary
DICTIONARY_MATCH_PATTERN = "/bundle.js"
# Match destinations - restrict dictionary to specific fetch destinations
# Empty list = match all destinations (per RFC 9842 Section 2.1.2)
DICTIONARY_MATCH_DEST = []  # Removed "script" restriction to simplify - matches all destinations

# Pre-compressed file extensions
# These files are pre-generated from Pat Meenan's shared-brotli-test repo
PRECOMPRESSED_FILES = {
    "dcb": ".sbr",  # Dictionary-compressed brotli (dcb encoding)
    "br": ".br",  # Standard brotli
    "gzip": ".gz",  # Gzip
}


@lru_cache(maxsize=20)
def load_file(filename: str) -> bytes:
    """Load a file from the static directory with caching."""
    filepath = os.path.join(STATIC_DIR, filename)
    with open(filepath, "rb") as f:
        return f.read()


def file_exists(filename: str) -> bool:
    """Check if a file exists in the static directory."""
    filepath = os.path.join(STATIC_DIR, filename)
    return os.path.exists(filepath)


@lru_cache(maxsize=10)
def get_file_hash(filename: str) -> bytes:
    """Get SHA-256 hash of a file (raw bytes)."""
    content = load_file(filename)
    return hashlib.sha256(content).digest()


def get_file_hash_hex(filename: str) -> str:
    """Get SHA-256 hash of a file (hex string)."""
    return get_file_hash(filename).hex()


def get_file_hash_base64(filename: str) -> str:
    """Get SHA-256 hash of a file (base64, as used in Available-Dictionary header)."""
    return base64.b64encode(get_file_hash(filename)).decode("ascii")


def parse_accept_encoding(header: str) -> set:
    """Parse Accept-Encoding header into a set of encodings."""
    if not header:
        return set()

    encodings = set()
    for part in header.split(","):
        # Handle quality values like "br;q=1.0"
        encoding = part.strip().split(";")[0].strip().lower()
        if encoding:
            encodings.add(encoding)

    return encodings


def parse_available_dictionary(header: str) -> str | None:
    """
    Parse Available-Dictionary header.

    Format: :<base64-encoded-sha256>:
    Returns the raw base64 string (without colons) or None.
    """
    if not header:
        return None

    header = header.strip()

    # Remove surrounding colons if present (RFC 9842 format)
    if header.startswith(":") and header.endswith(":"):
        header = header[1:-1]

    # Validate it looks like base64
    try:
        decoded = base64.b64decode(header)
        if len(decoded) == 32:
            return header
    except Exception:
        pass

    return None


def dictionary_hash_matches(
    available_dict_b64: str | None, dictionary_filename: str
) -> bool:
    """Check if the Available-Dictionary hash matches our dictionary file."""
    if not available_dict_b64:
        return False

    try:
        client_hash = base64.b64decode(available_dict_b64)
        our_hash = get_file_hash(dictionary_filename)
        return client_hash == our_hash
    except Exception:
        return False


def parse_dictionary_id(header: str | None) -> str | None:
    """
    Parse Dictionary-ID request header.

    Format: "<id>" (quoted string)
    Returns the ID without quotes, or None if not present/invalid.
    """
    if not header:
        return None

    header = header.strip()

    # Remove surrounding quotes if present
    if header.startswith('"') and header.endswith('"'):
        return header[1:-1]

    return header


def dictionary_id_matches(client_dict_id: str | None) -> bool:
    """Check if the client's Dictionary-ID matches our dictionary ID."""
    if not client_dict_id:
        return False
    return client_dict_id == DICTIONARY_ID


@app.route("/")
def index():
    """Info page with test instructions."""
    try:
        dict_hash = get_file_hash_base64(DICTIONARY_FILE)
        dict_size = len(load_file(DICTIONARY_FILE))
        bundle_size = len(load_file(BUNDLE_FILE))
    except FileNotFoundError:
        return jsonify(
            {
                "error": "Test files not found. Run 'python setup_files.py' first.",
            }
        ), 500

    return jsonify(
        {
            "service": "Shared Dictionary Test Origin",
            "description": "Test server for RFC 9842 shared dictionary compression passthrough",
            "endpoints": {
                "/dictionary.js": "Dictionary file with Use-As-Dictionary header",
                "/bundle.js": "Target file with dictionary/standard compression",
                "/health": "Health check endpoint",
            },
            "dictionary": {
                "file": DICTIONARY_FILE,
                "size_bytes": dict_size,
                "sha256_base64": dict_hash,
                "sha256_hex": get_file_hash_hex(DICTIONARY_FILE),
            },
            "bundle": {
                "file": BUNDLE_FILE,
                "size_bytes": bundle_size,
            },
            "test_curl_commands": {
                "1_fetch_dictionary": "curl -v http://localhost:8080/dictionary.js",
                "2_fetch_bundle_with_dictionary_dcb": f'curl -v -H "Accept-Encoding: dcb, br, gzip" -H "Available-Dictionary: :{dict_hash}:" -H "Dictionary-ID: \\"{DICTIONARY_ID}\\"" http://localhost:8080/bundle.js',
                "3_fetch_bundle_with_dictionary_dcz": f'curl -v -H "Accept-Encoding: dcz, br, gzip" -H "Available-Dictionary: :{dict_hash}:" -H "Dictionary-ID: \\"{DICTIONARY_ID}\\"" http://localhost:8080/bundle.js',
                "4_fetch_bundle_standard": 'curl -v -H "Accept-Encoding: br, gzip" http://localhost:8080/bundle.js',
            },
            "dictionary_id": DICTIONARY_ID,
        }
    )


@app.route("/health")
def health():
    """Health check endpoint."""
    log_request("/health")
    return jsonify({"status": "ok", "timestamp": time.time()})


@app.route("/test")
def test_page():
    """
    Serve the browser test page.

    This page loads dictionary.js and bundle.js as script tags,
    which allows Chrome to properly use the dictionary compression
    (since match-dest is set to "script").
    """
    log_request("/test")
    return render_template("test.html")


@app.route("/dictionary.js")
def serve_dictionary():
    """
    Serve the dictionary file with Use-As-Dictionary header.

    The Use-As-Dictionary header tells clients they can use this response
    as a compression dictionary for future requests matching the pattern.

    Per RFC 9842, the Use-As-Dictionary header format is:
        id="<id>", match="<pattern>", match-dest=("<dest1>" "<dest2>" ...)
    """
    try:
        content = load_file(DICTIONARY_FILE)
    except FileNotFoundError:
        log_request("/dictionary.js", compression_used="404")
        return jsonify(
            {"error": "Dictionary file not found. Run setup_files.py first."}
        ), 404

    dict_hash = get_file_hash_base64(DICTIONARY_FILE)

    # IMPORTANT: Serve dictionary UNCOMPRESSED
    # Chrome needs the raw bytes to compute the SHA-256 hash and register the dictionary.
    # If we compress it, Chrome decompresses for display but may not properly register
    # the dictionary for future use. Pat Meenan's implementation also serves dictionaries
    # uncompressed with a comment: "something weird is going on otherwise"
    response_content = content

    response = Response(response_content)
    response.headers["Content-Type"] = "application/javascript; charset=UTF-8"
    response.headers["Cache-Control"] = "public, max-age=604800"  # 7 days

    # Use-As-Dictionary header per RFC 9842
    # Format per RFC examples: match="<pattern>", match-dest=(...), id="<id>"
    # - match: URL pattern for resources that can use this dictionary (REQUIRED)
    # - match-dest: Restrict to specific fetch destinations (optional, empty = all)
    # - id: Unique identifier for the dictionary (optional, clients echo as Dictionary-ID)
    #
    # RFC 9842 Section 2.1.2: "An empty list for match-dest MUST match all destinations"
    # So we omit match-dest entirely when empty (equivalent to matching all)

    use_as_dict = f'match="{DICTIONARY_MATCH_PATTERN}", id="{DICTIONARY_ID}"'
    response.headers["Use-As-Dictionary"] = use_as_dict

    # Vary header for cache correctness
    response.headers["Vary"] = "Accept-Encoding"

    # No Content-Encoding header since we're serving uncompressed

    # Metadata headers for debugging/testing
    response.headers["X-Original-Size"] = str(len(content))
    response.headers["X-Compressed-Size"] = str(len(response_content))
    response.headers["X-Dictionary-Hash"] = get_file_hash_hex(DICTIONARY_FILE)
    response.headers["X-Dictionary-ID"] = DICTIONARY_ID

    # Log the request
    log_request(
        "/dictionary.js",
        compression_used="identity (uncompressed for dictionary registration)",
        extra_info={"size": str(len(content))},
    )

    return response


@app.route("/bundle.js")
def serve_bundle():
    """
    Serve the bundle file with appropriate compression using PRE-COMPRESSED files.

    This implementation serves pre-compressed files from Pat Meenan's shared-brotli-test
    repo instead of compressing on-the-fly. This ensures correct dictionary compression
    without requiring the brotli CLI tool.

    Pre-compressed files:
        - bundle.js.sbr  (1,976 bytes)  - Dictionary-compressed brotli
        - bundle.js.br   (82,312 bytes) - Standard brotli
        - bundle.js.gz   (94,843 bytes) - Gzip
        - bundle.js      (278,518 bytes) - Uncompressed

    Compression selection logic (per RFC 9842):
    1. If client has matching dictionary AND supports dcb:
       -> Return pre-compressed .sbr file with Content-Encoding: dcb
    2. Else if client supports br:
       -> Return pre-compressed .br file
    3. Else if client supports gzip:
       -> Return pre-compressed .gz file
    4. Else:
       -> Return uncompressed bundle.js
    """
    try:
        content = load_file(BUNDLE_FILE)
    except FileNotFoundError:
        return jsonify({"error": "Files not found. Run setup_files.py first."}), 404

    accept_encoding = parse_accept_encoding(request.headers.get("Accept-Encoding", ""))
    available_dict_header = request.headers.get("Available-Dictionary")
    available_dict = (
        parse_available_dictionary(available_dict_header)
        if available_dict_header
        else None
    )
    dict_id = parse_dictionary_id(request.headers.get("Dictionary-ID"))

    # Check if client has our dictionary
    has_matching_hash = dictionary_hash_matches(available_dict, DICTIONARY_FILE)
    has_matching_id = dictionary_id_matches(dict_id)
    has_matching_dictionary = has_matching_hash and has_matching_id

    # Determine which pre-compressed file to serve
    response_content = content
    content_encoding = "identity"
    compression_type = "identity"
    original_size = len(content)

    if has_matching_dictionary and "dcb" in accept_encoding:
        # Dictionary-compressed brotli - serve pre-compressed .sbr file
        sbr_file = BUNDLE_FILE + ".sbr"
        if file_exists(sbr_file):
            response_content = load_file(sbr_file)
            content_encoding = "dcb"
            compression_type = "dcb"
        else:
            logger.warning(f"Pre-compressed file {sbr_file} not found, falling back")

    if compression_type == "identity" and "br" in accept_encoding:
        # Standard brotli - serve pre-compressed .br file
        br_file = BUNDLE_FILE + ".br"
        if file_exists(br_file):
            response_content = load_file(br_file)
            content_encoding = "br"
            compression_type = "br"
        else:
            logger.warning(f"Pre-compressed file {br_file} not found, falling back")

    if compression_type == "identity" and "gzip" in accept_encoding:
        # Gzip - serve pre-compressed .gz file
        gz_file = BUNDLE_FILE + ".gz"
        if file_exists(gz_file):
            response_content = load_file(gz_file)
            content_encoding = "gzip"
            compression_type = "gzip"
        else:
            logger.warning(f"Pre-compressed file {gz_file} not found, falling back")

    response = Response(response_content)
    response.headers["Content-Type"] = "application/javascript; charset=UTF-8"
    # no-transform tells CDN not to modify/recompress the response
    response.headers["Cache-Control"] = "public, max-age=3600, no-transform"

    # Always set Vary header for correct caching
    response.headers["Vary"] = "Accept-Encoding, Available-Dictionary, Dictionary-ID"

    if content_encoding != "identity":
        response.headers["Content-Encoding"] = content_encoding

    # If we used dictionary compression, echo back the dictionary hash
    if compression_type == "dcb":
        dict_hash_b64 = get_file_hash_base64(DICTIONARY_FILE)
        response.headers["Content-Dictionary"] = f":{dict_hash_b64}:"

    # Metadata headers for debugging/testing
    compressed_size = len(response_content)
    compression_ratio = compressed_size / original_size if original_size > 0 else 1.0

    response.headers["X-Original-Size"] = str(original_size)
    response.headers["X-Compressed-Size"] = str(compressed_size)
    response.headers["X-Compression-Ratio"] = f"{compression_ratio:.4f}"
    response.headers["X-Compression-Type"] = compression_type
    response.headers["X-Dictionary-Hash"] = get_file_hash_hex(DICTIONARY_FILE)
    response.headers["X-Dictionary-ID"] = DICTIONARY_ID
    response.headers["X-Serving-Mode"] = "pre-compressed"

    # Echo back what we received for debugging
    response.headers["X-Received-Accept-Encoding"] = request.headers.get(
        "Accept-Encoding", ""
    )
    response.headers["X-Received-Available-Dictionary"] = request.headers.get(
        "Available-Dictionary", ""
    )
    response.headers["X-Received-Dictionary-ID"] = request.headers.get(
        "Dictionary-ID", ""
    )
    response.headers["X-Dictionary-Hash-Match"] = (
        "true" if has_matching_hash else "false"
    )
    response.headers["X-Dictionary-ID-Match"] = "true" if has_matching_id else "false"
    response.headers["X-Dictionary-Full-Match"] = (
        "true" if has_matching_dictionary else "false"
    )

    # Log the request with detailed info
    log_request(
        "/bundle.js",
        compression_used=compression_type,
        extra_info={
            "size": f"{original_size}->{compressed_size}",
            "ratio": f"{compression_ratio:.2%}",
            "dict_match": "YES" if has_matching_dictionary else "NO",
        },
    )

    return response


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shared Dictionary Test Origin Server")
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    # Check if files exist
    dict_path = os.path.join(STATIC_DIR, DICTIONARY_FILE)
    bundle_path = os.path.join(STATIC_DIR, BUNDLE_FILE)

    if not os.path.exists(dict_path) or not os.path.exists(bundle_path):
        print("=" * 60)
        print("ERROR: Test files not found!")
        print("Please run 'python setup_files.py' first to download them.")
        print("=" * 60)
        exit(1)

    # Print startup info
    print("=" * 60)
    print("Shared Dictionary Test Origin Server")
    print("=" * 60)
    print(f"Dictionary: {DICTIONARY_FILE}")
    print(f"  SHA-256:  {get_file_hash_hex(DICTIONARY_FILE)}")
    print(f"  Size:     {len(load_file(DICTIONARY_FILE)):,} bytes")
    print(f"Bundle:     {BUNDLE_FILE}")
    print(f"  Size:     {len(load_file(BUNDLE_FILE)):,} bytes")
    print("=" * 60)
    print(f"Listening on http://{args.host}:{args.port}")
    print("=" * 60)

    app.run(host=args.host, port=args.port, debug=args.debug)
