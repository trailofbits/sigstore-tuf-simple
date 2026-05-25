# sigstore-tuf-simple

A utility for quickly generating TUF (The Update Framework) repositories for testing Sigstore implementations. This tool allows you to create test TUF repositories with a mix of local and public Sigstore services, making it ideal for development, testing, and experimentation with Sigstore workflows.

## ⚠️ Security Notice

**This tool is designed for development and testing purposes only.** It should never be used in production environments. The generated TUF repositories are not suitable for production use as they may contain test certificates, keys, or configurations that lack proper security controls.

## What This Tool Does

This utility generates a complete TUF repository structure containing:

- **Root metadata**: Defines the trusted keys and roles
- **Targets metadata**: Lists available Sigstore service certificates and configurations
- **Snapshot metadata**: Contains hashes of all other metadata
- **Timestamp metadata**: Provides freshness guarantees
- **Target files**: Actual certificates, public keys, and configuration files for:
  - Fulcio Certificate Authority certificates
  - Rekor transparency log public keys
  - Certificate Transparency log public keys
  - Timestamping Authority certificates
  - Trusted root configurations
  - Signing configurations

## Prerequisites

- Go 1.24.0 or later
- Python 3 (for serving the TUF repository locally)

## Installation

```bash
git clone https://github.com/trailofbits/sigstore-tuf-simple.git
cd sigstore-tuf-simple
go build
```

## Usage

### Basic Usage

Generate a TUF repository with default Sigstore production services:

```bash
./sigstore-tuf-simple
python3 -m http.server 8081 -d tuf-repo
```

### Mixed Local and Public Services

Test with a local Rekor instance while using public Fulcio:

```bash
./sigstore-tuf-simple -rekor url=http://localhost:3000
python3 -m http.server 8081 -d tuf-repo
```

Example for local rekor-v2 deployment:
```bash
./sigstore-tuf-simple \
    -base-tuf staging \
    -rekor url=http://localhost:3003,origin=http://rekor-local,api-version=2,public-key=<path-to-rekor-tiles>/rekor-tiles/tests/testdata/pki/ed25519-pub-key.pem
python3 -m http.server 8081 -d tuf-repo
```

### Advanced Configuration

Configure multiple custom services:

```bash
./sigstore-tuf-simple \
    -rekor url=http://localhost:3000 \
    -fulcio url=http://localhost:5555,certificate-chain=fulcio.crt.pem,start-time=2006-01-02T15:04:05Z07:00 \
    -ctfe url=http://localhost:6962/test,public-key=/path/to/ctfe/pubkey.pem \
    -tsa url=http://localhost:3030 \
    -output custom-tuf-repo
python3 -m http.server 8081 -d custom-tuf-repo
```

## Command-Line Options

### Global Options

- `-base-tuf`: Base TUF repository ('default' for production or 'staging' for staging environment)
- `-output`: Output directory for the generated TUF repository (default: 'tuf-repo')
- `-signing-key`: Path to a persistent ed25519 signing key (PKCS#8 PEM). If the file exists it is reused; if it does not exist a new key is generated and saved there. Reusing the key lets you update an existing repository in place (see [Live Updates](#live-updates)). If empty (the default), an ephemeral key is generated each run and the repository cannot be updated in place.

### Service-Specific Options

Each service can be configured using comma-separated key-value pairs:

**Note:** All time values use RFC3339 format (e.g., `2006-01-02T15:04:05Z07:00` or `2023-12-25T10:30:00Z`).

#### Fulcio (`-fulcio`)
- **Required**: `url` - Fulcio service URL
- **Optional**:
  - `certificate-chain` - Path to PEM-encoded certificate chain file
  - `start-time` - Validity start time (RFC3339 format, e.g. `2023-12-25T10:30:00Z`)
  - `end-time` - Validity end time (RFC3339 format, e.g. `2023-12-25T10:30:00Z`)

#### Rekor (`-rekor`)
- **Required**: `url` - Rekor service URL
- **Optional**:
  - `public-key` - Path to PEM-encoded public key file
  - `start-time` - Validity start time (RFC3339 format, e.g. `2023-12-25T10:30:00Z`)
  - `end-time` - Validity end time (RFC3339 format, e.g. `2023-12-25T10:30:00Z`)
  - `api-version` - API version
  - `origin` - Log origin

#### Certificate Transparency (`-ctfe`)
- **Required**: `url` - CT log URL
- **Required**: `public-key` - Path to PEM-encoded public key file
- **Optional**:
  - `start-time` - Validity start time (RFC3339 format)
  - `end-time` - Validity end time (RFC3339 format)

#### Timestamping Authority (`-tsa`)
- **Required**: `url` - TSA service URL
- **Optional**:
  - `certificate-chain` - Path to PEM-encoded certificate chain file
  - `start-time` - Validity start time (RFC3339 format)
  - `end-time` - Validity end time (RFC3339 format)

#### OIDC Provider (`-oidc`)
- **Required**: `url` - OIDC provider URL

## Examples

### Local Development Environment

Set up a complete local Sigstore stack:

```bash
# Generate TUF repo for local services
./sigstore-tuf-simple \
    -rekor url=http://localhost:3000 \
    -fulcio url=http://localhost:5555 \
    -ctfe url=http://localhost:6962,public-key=./ct-pubkey.pem \
    -tsa url=http://localhost:3030

# Serve the repository
python3 -m http.server 8081 -d tuf-repo
```

### Testing with Staging Environment

```bash
# Use Sigstore staging services as base
./sigstore-tuf-simple -base-tuf staging -fulcio url=http://localhost:5555
python3 -m http.server 8081 -d tuf-repo
```

### Custom Certificate Chains

```bash
# Provide custom certificate files
./sigstore-tuf-simple \
    -fulcio url=https://my-fulcio.example.com,certificate-chain=./my-fulcio-certs.pem \
    -tsa url=https://my-tsa.example.com,certificate-chain=./my-tsa-certs.pem
```

## Live Updates

By default every run generates a fresh repository with new signing keys at
version 1. That is fine for one-shot setups, but a TUF client that has already
loaded the repository will reject a regenerated one (the keys no longer match the
root it pinned, and the versions do not increase).

To publish an update that a *running* client picks up on its next refresh — for
example to flip a Rekor v2 shard rollover into the signing config without
restarting the client — pass a persistent `-signing-key` and re-run against the
same `-output`:

```bash
# First run: create the repository and persist the signing key.
./sigstore-tuf-simple -base-tuf staging -signing-key tuf-key.pem -output tuf \
    -rekor url=http://localhost:8190,api-version=2,public-key=shardA.pub
python3 -m http.server 8085 -d tuf &

# Point your client at tuf/1.root.json and let it refresh.

# Later: re-run with the SAME key and new flags to publish an in-place update.
# The targets/snapshot/timestamp versions are bumped and re-signed with the same
# key; the root is left untouched, so the already-distributed root keeps validating
# the repository.
./sigstore-tuf-simple -base-tuf staging -signing-key tuf-key.pem -output tuf \
    -rekor url=http://localhost:8190,api-version=2,public-key=shardA.pub \
    -rekor url=http://localhost:8191,api-version=2,public-key=shardB.pub
```

Keep the key file outside the served `-output` directory so it is not exposed
over HTTP.

## Output Structure

The generated TUF repository follows this structure:

```
tuf-repo/
├── 1.root.json          # Root metadata (versioned)
├── 1.targets.json       # Targets metadata (versioned)
├── 1.snapshot.json      # Snapshot metadata (versioned)
├── timestamp.json       # Timestamp metadata (always current)
└── targets/             # Target files directory
    ├── <hash>.fulcio.1.pem
    ├── <hash>.rekor.1.pub
    ├── <hash>.ctfe.1.pub
    ├── <hash>.tsa.1.pem
    ├── <hash>.trusted_root.json
    └── <hash>.signing_config.v0.2.json
```

An in-place update (see [Live Updates](#live-updates)) adds new versioned
`N.targets.json` / `N.snapshot.json` files and overwrites `timestamp.json`; the
older metadata versions, along with the content-addressed `targets/` blobs they
reference, are left in place as consistent-snapshot history, so a client resolving
an earlier snapshot can still fetch its targets. `1.root.json` is unchanged.

## Testing

Run the test suite:

```bash
go test -v
```

## Contributing

This is a development tool intended for testing Sigstore implementations. Contributions that improve testing capabilities, add new service configurations, or enhance the developer experience are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full license text.

## Related Projects

- [Sigstore](https://sigstore.dev/) - The main Sigstore project
- [TUF](https://theupdateframework.io/) - The Update Framework
