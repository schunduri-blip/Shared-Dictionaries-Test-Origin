# Shared Dictionary Test Origin

A simple Flask server for testing RFC 9842 shared dictionary compression (dcb/dcz) passthrough.

Inspired by [Pat Meenan's dictionary-worker](https://github.com/pmeenan/dictionary-worker).

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Download test files
python setup_files.py

# Run server
python app.py

# Validate it works
python validate.py
```

## Endpoints

- `GET /` - Server info and test curl commands
- `GET /dictionary.js` - Dictionary file with `Use-As-Dictionary` header
- `GET /bundle.js` - Returns dcb/dcz compressed response when client sends matching `Available-Dictionary` and `Dictionary-ID` headers
- `GET /health` - Health check

## Test with curl

```bash
# Fetch dictionary
curl -v http://localhost:8080/dictionary.js

# Fetch bundle with dictionary compression (dcb)
curl -v \
  -H "Accept-Encoding: dcb, br, gzip" \
  -H "Available-Dictionary: :dLhW5VQBj+wNYFTFG8FYj78jhjONhRhCRHqVENsBVzI=:" \
  -H 'Dictionary-ID: "dict-v1"' \
  http://localhost:8080/bundle.js
```

## References

- [RFC 9842: Compression Dictionary Transport](https://datatracker.ietf.org/doc/rfc9842/)
- [Pat Meenan's dictionary-worker](https://github.com/pmeenan/dictionary-worker)
- [Pat Meenan's shared-brotli-test](https://github.com/pmeenan/shared-brotli-test)
