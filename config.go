// Package main provides configuration parsing for Sigstore services.
//
// This file contains parsers for command-line service specifications and utilities
// for fetching certificates and public keys from various sources.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TUFGeneratorConfig holds configuration for all Sigstore services needed
// to generate a TUF repository.
type TUFGeneratorConfig struct {
	fulcioCertAuthorities []root.CertificateAuthority
	ctLogs                map[string]*ServiceSpec
	rekorLogs             map[string]*ServiceSpec
	tsaCertAuthorities    []root.TimestampingAuthority
	oidcProviders         []OIDCProvider
	baseTempDir           string
	outputDir             string
}

// OIDCProvider represents an OIDC identity provider configuration.
type OIDCProvider struct {
	URL                 string
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
}

type ServiceSpec struct {
	root.TransparencyLog
	APIVersion uint32
}

// parseKVs parses a comma-separated key-value specification string.
// Input format: "key1=value1,key2=value2,key3=value3"
// Returns a map of key-value pairs or an error if parsing fails.
func parseKVs(spec string) (map[string]string, error) {
	kvs := make(map[string]string)

	// Handle empty string case
	if spec == "" {
		return kvs, nil
	}

	pairs := strings.Split(spec, ",")
	for _, pair := range pairs {
		// Skip empty pairs (from consecutive commas, leading/trailing commas)
		if strings.TrimSpace(pair) == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", pair)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Validate that key is not empty
		if key == "" {
			return nil, fmt.Errorf("empty key in key-value pair: %s", pair)
		}

		kvs[key] = value
	}
	return kvs, nil
}

// parseCerts parses PEM-encoded certificates from byte data.
// Returns a slice of parsed certificates or an error if none are found.
func parseCerts(contents []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for block, contents := pem.Decode(contents); block != nil; block, contents = pem.Decode(contents) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)

		if len(contents) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}

// parseFulcioSpec parses a Fulcio service specification.
// Required: url
// Optional: certificate-chain, start-time, end-time
func parseFulcioSpec(spec string) (root.CertificateAuthority, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, err
	}

	requiredKeys := []string{"url"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, fmt.Errorf("missing or empty required key '%s' in fulcio spec", key)
		}
	}

	var rootCert *x509.Certificate
	var intermediates []*x509.Certificate
	var certs []*x509.Certificate
	if certChain, ok := kvs["certificate-chain"]; ok && certChain != "" {
		contents, err := os.ReadFile(certChain)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate-chain: %w", err)
		}

		certs, err = parseCerts(contents)
		if err != nil {
			return nil, fmt.Errorf("parsing Fulcio certificate-chain: %w", err)
		}
	} else {
		fullCertURL := fmt.Sprintf("%s/api/v1/rootCert", kvs["url"])
		resp, err := http.Get(fullCertURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch root certificate from URL %s: %w", fullCertURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
		}

		contents, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		certs, err = parseCerts(contents)
		if err != nil {
			return nil, fmt.Errorf("parsing Fulcio root certificate: %w", err)
		}
	}
	rootCert = certs[len(certs)-1]
	if len(certs) > 1 {
		intermediates = certs[:len(certs)-1]
	}

	startTime := rootCert.NotBefore
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return nil, fmt.Errorf("parsing start-time: %w", err)
		}
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, fmt.Errorf("parsing end-time: %w", err)
		}
	}

	return &root.FulcioCertificateAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
		URI:                 kvs["url"],
	}, nil
}

// decodeTransparencyLogID converts a hex-encoded transparency log ID to bytes
func decodeTransparencyLogID(id string) ([]byte, error) {
	idBytes, err := hex.DecodeString(id)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transparency log ID: %w", err)
	}
	return idBytes, nil
}

func getPubKeyFromURL(url string) (crypto.PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key from URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return pubKey, nil
}

func getOrigin(fullUrl string) (string, error) {
	parsedURL, err := url.Parse(fullUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing url: %v", err)
	}
	prefixLen := len(parsedURL.Scheme) + len("://")
	if prefixLen >= len(parsedURL.String()) {
		return "", fmt.Errorf("error getting origin from URL %v", parsedURL)
	}
	origin := parsedURL.String()[len(parsedURL.Scheme)+len("://"):]
	return origin, nil
}

type getPublicKey func(kvs map[string]string) (crypto.PublicKey, error)

func parseTLog(spec string, getPublicKey getPublicKey) (*ServiceSpec, string, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, "", err
	}

	requiredKeys := []string{"url"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, "", fmt.Errorf("missing or empty required key '%s' in tlog spec", key)
		}
	}

	var pubKey crypto.PublicKey
	var idBytes []byte
	var id string
	if publicKey, ok := kvs["public-key"]; ok && publicKey != "" {
		pubKey, err = getPubKey(publicKey)
		if err != nil {
			return nil, "", fmt.Errorf("parsing public-key: %w", err)
		}
	} else {
		pubKey, err = getPublicKey(kvs)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get tlog public key: %w", err)
		}
	}

	var startTime time.Time
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return nil, "", fmt.Errorf("parsing start-time: %w", err)
		}
	} else {
		startTime = time.Now().Add(-1 * 24 * time.Hour)
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, "", fmt.Errorf("parsing end-time: %w", err)
		}
	} else {
		endTime = time.Now().Add(100 * 24 * time.Hour)
	}

	var apiVersion uint32 = 1
	if apiVersionStr, ok := kvs["api-version"]; ok && apiVersionStr != "" {
		var apiVersionUint64 uint64
		apiVersionUint64, err = strconv.ParseUint(apiVersionStr, 10, 32)
		if err != nil {
			return nil, "", fmt.Errorf("parsing api-version: %w", err)
		}
		apiVersion = uint32(apiVersionUint64)
	}

	switch apiVersion {
	case 1:
		// For rekor v1 we can use the SHA256 hash of the public key as the
		// transparency log ID to identify the log
		id, err = GetTransparencyLogID(pubKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get transparency log ID: %w", err)
		}
		idBytes, err = hex.DecodeString(id)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode transparency log ID: %w", err)
		}
	case 2:
		// For rekor v2 we need to look at the checkpoint key ID
		// https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md#trustedroot-lookup-by-checkpoint-key-id-rather-than-log-id
		origin, err := getOrigin(kvs["url"])
		if err != nil {
			return nil, "", fmt.Errorf("error getting origin from URL %v: %w", kvs["url"], err)
		}

		var idInt uint32
		idInt, idBytes, err = note.KeyHash(origin, pubKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get transparency log ID: %w", err)
		}

		id = fmt.Sprintf("%d", idInt)
	}

	tlog := &ServiceSpec{
		TransparencyLog: root.TransparencyLog{
			BaseURL:             kvs["url"],
			ID:                  idBytes,
			HashFunc:            crypto.SHA256,
			PublicKey:           pubKey,
			SignatureHashFunc:   getSignatureHashAlgo(pubKey),
			ValidityPeriodStart: startTime,
			ValidityPeriodEnd:   endTime,
		},
		APIVersion: apiVersion,
	}
	return tlog, id, nil
}

func parseRekorLog(spec string) (*ServiceSpec, string, error) {
	return parseTLog(spec, func(kvs map[string]string) (crypto.PublicKey, error) {
		apiVersion := 1
		if apiVersionStr, ok := kvs["api-version"]; ok && apiVersionStr != "" {
			apiVersionUint64, err := strconv.ParseUint(apiVersionStr, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing api-version: %w", err)
			}
			apiVersion = int(apiVersionUint64)
		}

		switch apiVersion {
		case 1:
			fullPublicKeyURL := fmt.Sprintf("%s/api/v1/log/publicKey", kvs["url"])
			return getPubKeyFromURL(fullPublicKeyURL)
		case 2:
			return nil, fmt.Errorf("rekor v2 does not have an endpoint for public key, you must provide a public-key")
		default:
			return nil, fmt.Errorf("unsupported API version: %d", apiVersion)
		}
	})
}

func parseCTLog(spec string) (*ServiceSpec, string, error) {
	return parseTLog(spec, func(kvs map[string]string) (crypto.PublicKey, error) {
		var tufClient *tuf.Client
		var err error
		u, err := url.Parse(kvs["url"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse url: %w", err)
		}
		host := u.Host

		if strings.HasSuffix(host, "sigstore.dev") {
			tufClient, err = tuf.DefaultClient()
		} else if strings.HasSuffix(host, "sigstage.dev") {
			options := tuf.DefaultOptions().WithRoot(tuf.StagingRoot()).WithRepositoryBaseURL(tuf.StagingMirror)
			tufClient, err = tuf.New(options)
		} else {
			return nil, fmt.Errorf("you must provide a public key for the CT log")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create tuf client: %w", err)
		}

		defaultTrustedRoot, err := root.GetTrustedRoot(tufClient)
		if err != nil {
			return nil, fmt.Errorf("failed to get trusted root: %w", err)
		}
		for _, log := range defaultTrustedRoot.CTLogs() {
			if log.BaseURL == kvs["url"] {
				return log.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("CT log not found")
	})
}

// parseOIDCSpec parses an OIDC provider specification.
// Required: url
// Optional: start-time, end-time
func parseOIDCSpec(spec string) (OIDCProvider, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return OIDCProvider{}, err
	}

	requiredKeys := []string{"url"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return OIDCProvider{}, fmt.Errorf("missing or empty required key '%s' in oidc spec", key)
		}
	}

	var startTime time.Time
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return OIDCProvider{}, fmt.Errorf("parsing start-time: %w", err)
		}
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return OIDCProvider{}, fmt.Errorf("parsing end-time: %w", err)
		}
	}

	return OIDCProvider{
		URL:                 kvs["url"],
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
	}, nil
}

func parseTSASpec(spec string) (root.TimestampingAuthority, error) {
	kvs, err := parseKVs(spec)
	if err != nil {
		return nil, err
	}

	requiredKeys := []string{"url"}
	for _, key := range requiredKeys {
		if val, ok := kvs[key]; !ok || val == "" {
			return nil, fmt.Errorf("missing or empty required key '%s' in tsa spec", key)
		}
	}

	var certs []*x509.Certificate
	if certChain, ok := kvs["certificate-chain"]; ok && certChain != "" {
		contents, err := os.ReadFile(certChain)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate-chain: %w", err)
		}
		certs, err = parseCerts(contents)
		if err != nil {
			return nil, fmt.Errorf("parsing TSA certificate-chain: %w", err)
		}
	} else {
		fullCertChainURL := fmt.Sprintf("%s/certchain", kvs["url"])
		resp, err := http.Get(fullCertChainURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch root certificate from URL %s: %w", fullCertChainURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
		}

		contents, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		certs, err = parseCerts(contents)
		if err != nil {
			return nil, fmt.Errorf("parsing TSA root certificate: %w", err)
		}
	}

	leafCert := certs[0]
	rootCert := certs[len(certs)-1]
	var intermediates []*x509.Certificate
	if len(certs) > 1 {
		intermediates = certs[1 : len(certs)-1]
	}

	startTime := leafCert.NotBefore
	if st, ok := kvs["start-time"]; ok && st != "" {
		startTime, err = time.Parse(time.RFC3339, st)
		if err != nil {
			return nil, fmt.Errorf("parsing start-time: %w", err)
		}
	}

	var endTime time.Time
	if et, ok := kvs["end-time"]; ok && et != "" {
		endTime, err = time.Parse(time.RFC3339, et)
		if err != nil {
			return nil, fmt.Errorf("parsing end-time: %w", err)
		}
	}

	return &root.SigstoreTimestampingAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		Leaf:                leafCert,
		ValidityPeriodStart: startTime,
		ValidityPeriodEnd:   endTime,
		URI:                 kvs["url"],
	}, nil
}

// GetTransparencyLogID generates a SHA256 hash of a DER-encoded public key.
// This follows RFC 6962 S3.2 for CT log ID generation.
func GetTransparencyLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

func getPubKey(path string) (crypto.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file %s: %w", path, err)
	}

	return cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
}

func getSignatureHashAlgo(pubKey crypto.PublicKey) crypto.Hash {
	var h crypto.Hash
	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		h = crypto.SHA256
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		default:
			h = crypto.SHA256
		}
	case ed25519.PublicKey:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	return h
}

// NewTUFGeneratorConfig creates a new TUF generator configuration from
// command-line service specifications.
func NewTUFGeneratorConfig(rekorConfigs []string, fulcioConfigs []string, ctfeConfigs []string, tsaConfigs []string, oidcConfigs []string, baseTempDir string, outputDir string) (*TUFGeneratorConfig, error) {
	rekorLogs := make(map[string]*ServiceSpec)
	for _, rekorConfig := range rekorConfigs {
		tlog, id, err := parseRekorLog(rekorConfig)
		if err != nil {
			return nil, fmt.Errorf("parsing rekor spec: %w", err)
		}
		rekorLogs[id] = tlog
	}

	fulcioCAs := make([]root.CertificateAuthority, 0, len(fulcioConfigs))
	for _, fulcioConfig := range fulcioConfigs {
		fulcioCA, err := parseFulcioSpec(fulcioConfig)
		if err != nil {
			return nil, fmt.Errorf("parsing fulcio spec: %w", err)
		}
		fulcioCAs = append(fulcioCAs, fulcioCA)
	}

	ctLogs := make(map[string]*ServiceSpec)
	for _, ctfeConfig := range ctfeConfigs {
		ctLog, id, err := parseCTLog(ctfeConfig)
		if err != nil {
			return nil, fmt.Errorf("parsing ctfe spec: %w", err)
		}
		ctLogs[id] = ctLog
	}

	tsaCAs := make([]root.TimestampingAuthority, 0, len(tsaConfigs))
	for _, tsaConfig := range tsaConfigs {
		tsaCA, err := parseTSASpec(tsaConfig)
		if err != nil {
			return nil, fmt.Errorf("parsing tsa spec: %w", err)
		}
		tsaCAs = append(tsaCAs, tsaCA)
	}

	oidcProviders := make([]OIDCProvider, 0, len(oidcConfigs))
	for _, oidcConfig := range oidcConfigs {
		oidcProvider, err := parseOIDCSpec(oidcConfig)
		if err != nil {
			return nil, fmt.Errorf("parsing oidc spec: %w", err)
		}
		oidcProviders = append(oidcProviders, oidcProvider)
	}

	return &TUFGeneratorConfig{
		fulcioCertAuthorities: fulcioCAs,
		ctLogs:                ctLogs,
		rekorLogs:             rekorLogs,
		tsaCertAuthorities:    tsaCAs,
		oidcProviders:         oidcProviders,
		baseTempDir:           baseTempDir,
		outputDir:             outputDir,
	}, nil
}
