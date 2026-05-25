// Package main provides TUF repository generation functionality.
//
// This file contains the core logic for creating TUF metadata and target files
// from Sigstore service configurations.
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// TUFGenerator handles the creation of TUF repositories from service configurations.
type TUFGenerator struct {
	config *TUFGeneratorConfig
}

// NewTUFGenerator creates a new TUF generator with the given configuration.
func NewTUFGenerator(config *TUFGeneratorConfig) *TUFGenerator {
	return &TUFGenerator{
		config: config,
	}
}

func fulcioCAToServices(fulcioCAList []root.CertificateAuthority) []root.Service {
	services := make([]root.Service, 0, len(fulcioCAList))
	for _, fulcioCA := range fulcioCAList {
		fulcioCA, ok := fulcioCA.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		services = append(services, root.Service{
			URL:                 fulcioCA.URI,
			MajorAPIVersion:     1,
			ValidityPeriodStart: fulcioCA.ValidityPeriodStart,
			ValidityPeriodEnd:   fulcioCA.ValidityPeriodEnd,
		})
	}
	return services
}

func oidcProviderToServices(oidcProviders []OIDCProvider) []root.Service {
	services := make([]root.Service, 0, len(oidcProviders))
	for _, oidcProvider := range oidcProviders {
		services = append(services, root.Service{
			URL:                 oidcProvider.URL,
			MajorAPIVersion:     1,
			ValidityPeriodStart: oidcProvider.ValidityPeriodStart,
			ValidityPeriodEnd:   oidcProvider.ValidityPeriodEnd,
		})
	}
	return services
}

func tsaToServices(tsaList []root.TimestampingAuthority) []root.Service {
	services := make([]root.Service, 0, len(tsaList))
	for _, tsa := range tsaList {
		tsa, ok := tsa.(*root.SigstoreTimestampingAuthority)
		if !ok {
			continue
		}
		services = append(services, root.Service{
			URL:                 tsa.URI,
			MajorAPIVersion:     1,
			ValidityPeriodStart: tsa.ValidityPeriodStart,
			ValidityPeriodEnd:   tsa.ValidityPeriodEnd,
		})
	}
	return services
}

func rekorLogToServices(rekorLogs map[string]*ServiceSpec) []root.Service {
	services := make([]root.Service, 0, len(rekorLogs))
	for _, rekorLog := range rekorLogs {
		url := rekorLog.ServiceURL
		if url == "" {
			url = rekorLog.BaseURL
		}
		services = append(services, root.Service{
			URL:                 url,
			MajorAPIVersion:     rekorLog.APIVersion,
			ValidityPeriodStart: rekorLog.ValidityPeriodStart,
			ValidityPeriodEnd:   rekorLog.ValidityPeriodEnd,
		})
	}
	return services
}

func writeCerts(certs []*x509.Certificate, tempDir string, name string) (string, error) {
	var pemData []byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	tempFilePath := filepath.Join(tempDir, name)
	err := os.WriteFile(tempFilePath, pemData, 0644)
	if err != nil {
		return "", err
	}
	return tempFilePath, nil
}

func writePubKey(pubKey crypto.PublicKey, tempDir string, name string) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	tempFilePath := filepath.Join(tempDir, name)
	err = os.WriteFile(tempFilePath, pubKeyBytes, 0644)
	if err != nil {
		return "", err
	}
	return tempFilePath, nil
}

func getFulcioTargets(config *TUFGeneratorConfig, tempDir string) []targetInfo {
	targets := []targetInfo{}

	for i, fulcioCA := range config.fulcioCertAuthorities {
		fulcioCA, ok := fulcioCA.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}

		// Concatenate root and intermediate certificates
		certs := []*x509.Certificate{fulcioCA.Root}
		certs = append(certs, fulcioCA.Intermediates...)

		name := fmt.Sprintf("fulcio.%d.pem", i+1)
		tempFilePath, err := writeCerts(certs, tempDir, name)
		if err != nil {
			continue
		}

		targets = append(targets, targetInfo{
			name:   name,
			source: tempFilePath,
		})
	}
	return targets
}

func getTSATargets(config *TUFGeneratorConfig, tempDir string) []targetInfo {
	targets := []targetInfo{}

	for i, tsa := range config.tsaCertAuthorities {
		tsa, ok := tsa.(*root.SigstoreTimestampingAuthority)
		if !ok {
			continue
		}

		certs := []*x509.Certificate{tsa.Leaf}
		certs = append(certs, tsa.Intermediates...)
		certs = append(certs, tsa.Root)

		name := fmt.Sprintf("tsa.%d.pem", i+1)
		tempFilePath, err := writeCerts(certs, tempDir, name)
		if err != nil {
			continue
		}

		targets = append(targets, targetInfo{
			name:   name,
			source: tempFilePath,
		})
	}
	return targets
}

func getCTLogTargets(config *TUFGeneratorConfig, tempDir string) []targetInfo {
	targets := []targetInfo{}
	i := 0
	for _, ctLog := range config.ctLogs {
		i = i + 1
		name := fmt.Sprintf("ctfe.%d.pub", i)
		tempFilePath, err := writePubKey(ctLog.PublicKey, tempDir, name)
		if err != nil {
			continue
		}

		targets = append(targets, targetInfo{
			name:   name,
			source: tempFilePath,
		})
	}
	return targets
}

func getRekorLogTargets(config *TUFGeneratorConfig, tempDir string) []targetInfo {
	targets := []targetInfo{}
	i := 0
	for _, rekorLog := range config.rekorLogs {
		i = i + 1
		name := fmt.Sprintf("rekor.%d.pub", i)
		tempFilePath, err := writePubKey(rekorLog.PublicKey, tempDir, name)
		if err != nil {
			continue
		}

		targets = append(targets, targetInfo{
			name:   name,
			source: tempFilePath,
		})
	}
	return targets
}

func generateTrustedRoot(config *TUFGeneratorConfig, tempDir string) targetInfo {
	ctLogs := make(map[string]*root.TransparencyLog)
	for k, v := range config.ctLogs {
		ctLogs[k] = &v.TransparencyLog
	}

	rekorLogs := make(map[string]*root.TransparencyLog)
	for k, v := range config.rekorLogs {
		rekorLogs[k] = &v.TransparencyLog
	}

	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		config.fulcioCertAuthorities,
		ctLogs,
		config.tsaCertAuthorities,
		rekorLogs,
	)
	if err != nil {
		return targetInfo{}
	}

	trBytes, err := trustedRoot.MarshalJSON()
	if err != nil {
		return targetInfo{}
	}

	tempFilePath := filepath.Join(tempDir, "trusted_root.json")
	err = os.WriteFile(tempFilePath, trBytes, 0600)
	if err != nil {
		return targetInfo{}
	}

	return targetInfo{
		name:   "trusted_root.json",
		source: tempFilePath,
	}
}

func generateSigningConfig(config *TUFGeneratorConfig, tempDir string) targetInfo {
	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		fulcioCAToServices(config.fulcioCertAuthorities),
		oidcProviderToServices(config.oidcProviders),
		rekorLogToServices(config.rekorLogs),
		root.ServiceConfiguration{
			Selector: prototrustroot.ServiceSelector_ANY,
		},
		tsaToServices(config.tsaCertAuthorities),
		root.ServiceConfiguration{
			Selector: prototrustroot.ServiceSelector_ANY,
		},
	)
	if err != nil {
		return targetInfo{}
	}

	scBytes, err := signingConfig.MarshalJSON()
	if err != nil {
		return targetInfo{}
	}

	tempFilePath := filepath.Join(tempDir, "signing_config.v0.2.json")
	err = os.WriteFile(tempFilePath, scBytes, 0600)
	if err != nil {
		return targetInfo{}
	}

	return targetInfo{
		name:   "signing_config.v0.2.json",
		source: tempFilePath,
	}
}

func getTargets(config *TUFGeneratorConfig, tempDir string) []targetInfo {
	targets := []targetInfo{}
	targets = append(targets, getFulcioTargets(config, tempDir)...)
	targets = append(targets, getTSATargets(config, tempDir)...)
	targets = append(targets, getCTLogTargets(config, tempDir)...)
	targets = append(targets, getRekorLogTargets(config, tempDir)...)
	targets = append(targets, generateTrustedRoot(config, tempDir))
	targets = append(targets, generateSigningConfig(config, tempDir))
	return targets
}

// Code copied and adapted from https://github.com/sigstore/cosign/blob/76faaff0cfce9d8fd3892a125426f9f7ed0f9508/test/e2e_test.go#L361
// Licensed under the Apache License, Version 2.0 (the "License");
// http://www.apache.org/licenses/LICENSE-2.0

// targetInfo represents a TUF target file with metadata.
type targetInfo struct {
	name   string
	source string
	usage  string
}

// copyFile copies a file from source to destination path.
func copyFile(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer f.Close()
	cp, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	defer cp.Close()
	_, err = io.Copy(cp, f)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}
	return nil
}

// downloadTargets writes each target as a content-addressed <sha256>.<name> blob
// under td/targets and records it in targetsMeta. When clean is true the targets
// directory is wiped first (a fresh repository); when false the existing blobs are
// kept so that the still-published older N.targets.json metadata keeps resolving —
// changed targets land under new hashes and the old blobs remain as
// consistent-snapshot history.
func downloadTargets(td string, targets []targetInfo, targetsMeta *metadata.Metadata[metadata.TargetsType], clean bool) error {
	targetsDir := filepath.Join(td, "targets")
	if clean {
		if err := os.RemoveAll(targetsDir); err != nil {
			return err
		}
	}
	err := os.MkdirAll(targetsDir, 0700)
	if err != nil {
		return err
	}
	targetsMeta.Signed.Targets = make(map[string]*metadata.TargetFiles)
	for _, target := range targets {
		data, err := os.ReadFile(target.source)
		if err != nil {
			return err
		}
		hashBytes := sha256.Sum256(data)
		hashString := hex.EncodeToString(hashBytes[:])
		hashedTargetName := fmt.Sprintf("%s.%s", hashString, target.name)

		targetLocalPath := filepath.Join(targetsDir, hashedTargetName)
		err = copyFile(target.source, targetLocalPath)
		if err != nil {
			return err
		}
		targetFileInfo, err := metadata.TargetFile().FromFile(targetLocalPath, "sha256")
		if err != nil {
			return err
		}
		if target.usage != "" {
			customMsg := fmt.Sprintf(`{"sigstore":{"usage": "%s"}}`, target.usage)
			custom := json.RawMessage([]byte(customMsg))
			targetFileInfo.Custom = &custom
		}

		targetsMeta.Signed.Targets[target.name] = targetFileInfo
	}
	return nil
}

type tufData struct {
	publicKey *metadata.Key
	signer    signature.Signer
	root      *metadata.Metadata[metadata.RootType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	targets   *metadata.Metadata[metadata.TargetsType]
}

func keyAndSigner(private ed25519.PrivateKey) (*metadata.Key, signature.Signer, error) {
	public, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return nil, nil, err
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return public, signer, nil
}

// loadOrCreateSigningKey returns the ed25519 key used to sign every role.
//
// With path set it persists the key as PKCS#8 PEM so later runs reuse it: that
// is what lets an existing repository be updated in place (an update re-signed
// with a different key would not validate against the already-published root).
// loaded reports whether the key came from an existing file, which the caller
// uses to tell an update apart from a fresh repository sharing the directory.
// With path empty an ephemeral key is generated and loaded is false.
func loadOrCreateSigningKey(path string) (key *metadata.Key, signer signature.Signer, loaded bool, err error) {
	if path != "" {
		pemBytes, readErr := os.ReadFile(path)
		switch {
		case readErr == nil:
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				return nil, nil, false, fmt.Errorf("decoding signing key %s: no PEM block found", path)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, false, fmt.Errorf("parsing signing key %s: %w", path, err)
			}
			private, ok := parsed.(ed25519.PrivateKey)
			if !ok {
				return nil, nil, false, fmt.Errorf("signing key %s is %T, want ed25519", path, parsed)
			}
			key, signer, err = keyAndSigner(private)
			return key, signer, true, err
		case !errors.Is(readErr, os.ErrNotExist):
			return nil, nil, false, fmt.Errorf("reading signing key %s: %w", path, readErr)
		}
	}

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, false, err
	}
	if path != "" {
		if err := saveSigningKey(path, private); err != nil {
			return nil, nil, false, err
		}
	}
	key, signer, err = keyAndSigner(private)
	return key, signer, false, err
}

func saveSigningKey(path string, private ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("marshaling signing key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return fmt.Errorf("writing signing key %s: %w", path, err)
	}
	return nil
}

func newTUF(td string, targetList []targetInfo, public *metadata.Key, signer signature.Signer) (*tufData, error) {
	// source: https://github.com/theupdateframework/go-tuf/blob/v2.0.2/examples/repository/basic_repository.go
	expiration := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(expiration)
	err := downloadTargets(td, targetList, targets, true)
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(expiration)
	timestamp := metadata.Timestamp(expiration)
	// updateTUF never re-issues the root, so give it a long life; otherwise an
	// in-place update would stop validating once the original 1-day root expired.
	root := metadata.Root(time.Now().AddDate(1, 0, 0).UTC())

	tuf := &tufData{
		publicKey: public,
		signer:    signer,
		root:      root,
		snapshot:  snapshot,
		timestamp: timestamp,
		targets:   targets,
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		err := tuf.root.Signed.AddKey(tuf.publicKey, name)
		if err != nil {
			return nil, err
		}
		switch name {
		case "targets":
			_, err = tuf.targets.Sign(tuf.signer)
		case "snapshot":
			_, err = tuf.snapshot.Sign(tuf.signer)
		case "timestamp":
			_, err = tuf.timestamp.Sign(tuf.signer)
		case "root":
			_, err = tuf.root.Sign(tuf.signer)
		}
		if err != nil {
			return nil, err
		}
	}
	err = tuf.targets.ToFile(filepath.Join(td, fmt.Sprintf("%d.%s.json", tuf.targets.Signed.Version, "targets")), false)
	if err != nil {
		return nil, err
	}
	err = tuf.snapshot.ToFile(filepath.Join(td, fmt.Sprintf("%d.%s.json", tuf.snapshot.Signed.Version, "snapshot")), false)
	if err != nil {
		return nil, err
	}
	err = tuf.timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
	if err != nil {
		return nil, err
	}
	err = tuf.root.ToFile(filepath.Join(td, fmt.Sprintf("%d.%s.json", tuf.root.Signed.Version, "root")), false)
	if err != nil {
		return nil, err
	}

	err = tuf.root.VerifyDelegate("root", tuf.root)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("targets", tuf.targets)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("snapshot", tuf.snapshot)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("timestamp", tuf.timestamp)
	if err != nil {
		return nil, err
	}

	return tuf, nil
}

// repoVersions holds the current metadata versions of a previously generated
// repository. root is kept at version 1 for the life of the repository (its keys
// never change), so only the snapshot-tracked roles are recorded here.
type repoVersions struct {
	targets   int64
	snapshot  int64
	timestamp int64
}

// readRepoVersions reads the current versions of a repository previously written
// to td, following timestamp -> snapshot -> targets. found is false when td does
// not yet contain a repository.
func readRepoVersions(td string) (versions repoVersions, found bool, err error) {
	timestamp, err := metadata.Timestamp().FromFile(filepath.Join(td, "timestamp.json"))
	if errors.Is(err, os.ErrNotExist) {
		return repoVersions{}, false, nil
	}
	if err != nil {
		return repoVersions{}, false, fmt.Errorf("reading existing timestamp: %w", err)
	}
	snapshotVer := timestamp.Signed.Meta["snapshot.json"].Version
	snapshot, err := metadata.Snapshot().FromFile(filepath.Join(td, fmt.Sprintf("%d.snapshot.json", snapshotVer)))
	if err != nil {
		return repoVersions{}, false, fmt.Errorf("reading existing snapshot: %w", err)
	}
	return repoVersions{
		targets:   snapshot.Signed.Meta["targets.json"].Version,
		snapshot:  snapshotVer,
		timestamp: timestamp.Signed.Version,
	}, true, nil
}

// updateTUF publishes a new version of an existing repository: it re-signs the
// targets, snapshot and timestamp with the persisted key at incremented
// versions. The root is left untouched (same key, same delegations) so the
// already-distributed root keeps validating the repository, which is what lets a
// running TUF client pick up the change on its next refresh without a restart.
func updateTUF(td string, targetList []targetInfo, signer signature.Signer, prev repoVersions) error {
	expiration := time.Now().AddDate(0, 0, 1).UTC()

	targets := metadata.Targets(expiration)
	targets.Signed.Version = prev.targets + 1
	// Keep the previous content-addressed blobs in place: the older N.targets.json
	// metadata stays published, so a client resolving an earlier snapshot must still
	// be able to fetch the targets it references.
	if err := downloadTargets(td, targetList, targets, false); err != nil {
		return err
	}

	snapshot := metadata.Snapshot(expiration)
	snapshot.Signed.Version = prev.snapshot + 1
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(targets.Signed.Version)

	timestamp := metadata.Timestamp(expiration)
	timestamp.Signed.Version = prev.timestamp + 1
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshot.Signed.Version)

	for _, m := range []signable{targets, snapshot, timestamp} {
		if _, err := m.Sign(signer); err != nil {
			return err
		}
	}

	// The root never changes, so it stays at version 1. Verifying the new metadata
	// against it catches a mismatched -signing-key before anything is written.
	root, err := metadata.Root().FromFile(filepath.Join(td, "1.root.json"))
	if err != nil {
		return fmt.Errorf("reading existing root (regenerate with a fresh -output if it is missing): %w", err)
	}
	// updateTUF never re-issues the root, so an expired root cannot be refreshed
	// here. Publishing against it would only produce metadata every client rejects,
	// so fail with a clear message instead. (Roots created before the long-lived
	// root change expire after a day and hit this quickly.)
	if root.Signed.IsExpired(time.Now()) {
		return fmt.Errorf("existing root expired on %s; updateTUF cannot re-issue it, regenerate the repository with a fresh -output", root.Signed.Expires.UTC().Format(time.RFC3339))
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		return fmt.Errorf("verifying updated targets (wrong -signing-key?): %w", err)
	}
	if err := root.VerifyDelegate("snapshot", snapshot); err != nil {
		return fmt.Errorf("verifying updated snapshot: %w", err)
	}
	if err := root.VerifyDelegate("timestamp", timestamp); err != nil {
		return fmt.Errorf("verifying updated timestamp: %w", err)
	}

	if err := targets.ToFile(filepath.Join(td, fmt.Sprintf("%d.targets.json", targets.Signed.Version)), false); err != nil {
		return err
	}
	if err := snapshot.ToFile(filepath.Join(td, fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)), false); err != nil {
		return err
	}
	return timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
}

type signable interface {
	Sign(signature.Signer) (*metadata.Signature, error)
}

// Generate writes a complete TUF repository to the configured output directory.
//
// When a persistent signing key is configured (see signingKeyPath) and the
// output directory already holds a repository, the existing metadata is updated
// in place (versions bumped, root reused) instead of regenerated from scratch.
func (g *TUFGenerator) Generate() error {
	tempDir, err := os.MkdirTemp(g.config.baseTempDir, "tuf-repo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	targets := getTargets(g.config, tempDir)

	public, signer, keyLoaded, err := loadOrCreateSigningKey(g.config.signingKeyPath)
	if err != nil {
		return fmt.Errorf("preparing signing key: %w", err)
	}

	// An update is only possible with the original key. A freshly generated key
	// (keyLoaded == false) means this is a new repository even if a stale one
	// happens to share the directory, so fall through to a full regeneration.
	if keyLoaded {
		prev, found, err := readRepoVersions(g.config.outputDir)
		if err != nil {
			return err
		}
		if found {
			if err := updateTUF(g.config.outputDir, targets, signer, prev); err != nil {
				return fmt.Errorf("failed to update tuf: %w", err)
			}
			return nil
		}
	}

	if _, err = newTUF(g.config.outputDir, targets, public, signer); err != nil {
		return fmt.Errorf("failed to create tuf: %w", err)
	}
	return nil
}
