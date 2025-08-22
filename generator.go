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

func oidcProviderToServices(oidcProviders []string) []root.Service {
	services := make([]root.Service, 0, len(oidcProviders))
	for _, oidcProvider := range oidcProviders {
		services = append(services, root.Service{
			URL:             oidcProvider,
			MajorAPIVersion: 1,
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
		services = append(services, root.Service{
			URL:                 rekorLog.BaseURL,
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

func downloadTargets(td string, targets []targetInfo, targetsMeta *metadata.Metadata[metadata.TargetsType]) error {
	targetsDir := filepath.Join(td, "targets")
	err := os.RemoveAll(targetsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(targetsDir, 0700)
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

func newKey() (*metadata.Key, signature.Signer, error) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return public, signer, nil
}

func newTUF(td string, targetList []targetInfo) (*tufData, error) {
	// source: https://github.com/theupdateframework/go-tuf/blob/v2.0.2/examples/repository/basic_repository.go
	expiration := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(expiration)
	err := downloadTargets(td, targetList, targets)
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(expiration)
	timestamp := metadata.Timestamp(expiration)
	root := metadata.Root(expiration)

	public, signer, err := newKey()
	if err != nil {
		return nil, err
	}

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

// Generate creates a complete TUF repository in the configured output directory.
// This includes generating all metadata files and copying target files.
func (g *TUFGenerator) Generate() error {
	tempDir, err := os.MkdirTemp(g.config.baseTempDir, "tuf-repo-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tempDir)

	targets := getTargets(g.config, tempDir)
	_, err = newTUF(g.config.outputDir, targets)
	if err != nil {
		return fmt.Errorf("failed to create tuf: %w", err)
	}
	return nil
}
