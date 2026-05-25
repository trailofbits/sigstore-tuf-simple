package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// testRepoConfig builds a generator config with a self-signed Fulcio CA and a
// Rekor v1 log keyed by a local public key, so a full repository can be
// generated without any network access.
func testRepoConfig(t *testing.T, outputDir, signingKeyPath string) *TUFGeneratorConfig {
	t.Helper()
	specDir := t.TempDir()

	rootCert, _ := createTestCertificate(t, true, nil, nil)
	chainFile := filepath.Join(specDir, "fulcio.pem")
	writeCertificateChainToFile(t, []*x509.Certificate{rootCert}, chainFile)

	pubKey, _ := createTestPublicKey(t)
	pubKeyFile := filepath.Join(specDir, "rekor.pub")
	writePublicKeyToFile(t, pubKey, pubKeyFile)

	cfg, err := NewTUFGeneratorConfig(
		[]string{fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile)},
		[]string{fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s", chainFile)},
		nil, nil, nil,
		t.TempDir(), outputDir, signingKeyPath,
	)
	if err != nil {
		t.Fatalf("NewTUFGeneratorConfig: %v", err)
	}
	return cfg
}

func timestampVersion(t *testing.T, repoDir string) int64 {
	t.Helper()
	ts, err := metadata.Timestamp().FromFile(filepath.Join(repoDir, "timestamp.json"))
	if err != nil {
		t.Fatalf("reading timestamp: %v", err)
	}
	return ts.Signed.Version
}

func rootKeyIDs(t *testing.T, repoDir string) string {
	t.Helper()
	root, err := metadata.Root().FromFile(filepath.Join(repoDir, "1.root.json"))
	if err != nil {
		t.Fatalf("reading root: %v", err)
	}
	ids := make([]string, 0, len(root.Signed.Keys))
	for id := range root.Signed.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func TestGeneratePersistentKeyUpdatesInPlace(t *testing.T) {
	outputDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signing.pem")

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("init Generate: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("signing key was not persisted: %v", err)
	}
	if got := timestampVersion(t, outputDir); got != 1 {
		t.Fatalf("after init, timestamp version = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "1.targets.json")); err != nil {
		t.Fatalf("1.targets.json missing after init: %v", err)
	}
	rootBefore := rootKeyIDs(t, outputDir)

	// Re-running with the same key against the same output must update in place,
	// not regenerate from scratch.
	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("update Generate: %v", err)
	}
	if got := timestampVersion(t, outputDir); got != 2 {
		t.Fatalf("after update, timestamp version = %d, want 2", got)
	}
	for _, f := range []string{"2.targets.json", "2.snapshot.json"} {
		if _, err := os.Stat(filepath.Join(outputDir, f)); err != nil {
			t.Fatalf("%s missing after update: %v", f, err)
		}
	}
	if rootAfter := rootKeyIDs(t, outputDir); rootAfter != rootBefore {
		t.Fatalf("root keys changed across update: before=%s after=%s", rootBefore, rootAfter)
	}

	// The bumped metadata must still validate against the original root, which is
	// what a running TUF client relies on to accept the update.
	root, err := metadata.Root().FromFile(filepath.Join(outputDir, "1.root.json"))
	if err != nil {
		t.Fatalf("reading root: %v", err)
	}
	targets, err := metadata.Targets().FromFile(filepath.Join(outputDir, "2.targets.json"))
	if err != nil {
		t.Fatalf("reading updated targets: %v", err)
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		t.Fatalf("updated targets do not verify against the original root: %v", err)
	}
}

// targetBlobs returns the set of content-addressed blob filenames currently in
// the repository's targets/ directory.
func targetBlobs(t *testing.T, repoDir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoDir, "targets"))
	if err != nil {
		t.Fatalf("reading targets dir: %v", err)
	}
	blobs := make(map[string]bool, len(entries))
	for _, e := range entries {
		blobs[e.Name()] = true
	}
	return blobs
}

func TestUpdatePreservesOldTargetBlobs(t *testing.T) {
	outputDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signing.pem")

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("init Generate: %v", err)
	}
	before := targetBlobs(t, outputDir)

	// A second run with the same key but freshly generated service material changes
	// target content, so the update must publish new content-addressed blobs without
	// deleting the ones the still-published 1.targets.json references.
	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("update Generate: %v", err)
	}
	after := targetBlobs(t, outputDir)

	for blob := range before {
		if !after[blob] {
			t.Errorf("target blob %q was deleted on update, breaking consistent-snapshot history", blob)
		}
	}
	if len(after) <= len(before) {
		t.Fatalf("expected the update to add new content-addressed blobs: before=%d after=%d", len(before), len(after))
	}
}

func TestGenerateRejectsMismatchedSigningKey(t *testing.T) {
	outputDir := t.TempDir()
	keyA := filepath.Join(t.TempDir(), "keyA.pem")

	// Create the repository, signed and rooted with key A.
	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyA)).Generate(); err != nil {
		t.Fatalf("init Generate: %v", err)
	}

	// A different, valid key that the already-published root does not trust.
	keyB := filepath.Join(t.TempDir(), "keyB.pem")
	_, privB, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key B: %v", err)
	}
	if err := saveSigningKey(keyB, privB); err != nil {
		t.Fatalf("saving key B: %v", err)
	}

	// Updating the key-A repository with key B must be rejected.
	err = NewTUFGenerator(testRepoConfig(t, outputDir, keyB)).Generate()
	if err == nil {
		t.Fatal("expected Generate to reject a mismatched signing key, got nil")
	}
	if !strings.Contains(err.Error(), "wrong -signing-key") {
		t.Fatalf("error did not point at the wrong signing key: %v", err)
	}

	// The rejection must happen before anything is written: the verify-before-write
	// ordering means no new metadata is published when the key does not match.
	if _, statErr := os.Stat(filepath.Join(outputDir, "2.targets.json")); !os.IsNotExist(statErr) {
		t.Fatalf("2.targets.json must not exist after a rejected update: %v", statErr)
	}
	if got := timestampVersion(t, outputDir); got != 1 {
		t.Fatalf("timestamp version = %d after a rejected update, want 1 (unchanged)", got)
	}
}

func TestUpdateFailsWithMissingRoot(t *testing.T) {
	outputDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signing.pem")

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("init Generate: %v", err)
	}
	if err := os.Remove(filepath.Join(outputDir, "1.root.json")); err != nil {
		t.Fatalf("removing root: %v", err)
	}

	err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate()
	if err == nil {
		t.Fatal("expected Generate to fail when 1.root.json is missing, got nil")
	}
	if !strings.Contains(err.Error(), "reading existing root") {
		t.Fatalf("error did not mention the missing root: %v", err)
	}
}

func TestUpdateFailsWithExpiredRoot(t *testing.T) {
	outputDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "signing.pem")

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate(); err != nil {
		t.Fatalf("init Generate: %v", err)
	}

	// Back-date the root's expiry and re-sign it with the persisted key so it stays
	// validly signed but expired, mimicking a long-lived repository (or one created
	// by the pre-change 1-day-root binary) whose root has since lapsed.
	_, signer, _, err := loadOrCreateSigningKey(keyPath)
	if err != nil {
		t.Fatalf("loading signing key: %v", err)
	}
	rootPath := filepath.Join(outputDir, "1.root.json")
	root, err := metadata.Root().FromFile(rootPath)
	if err != nil {
		t.Fatalf("reading root: %v", err)
	}
	root.Signed.Expires = time.Now().Add(-time.Hour).UTC()
	root.ClearSignatures()
	if _, err := root.Sign(signer); err != nil {
		t.Fatalf("re-signing root: %v", err)
	}
	if err := root.ToFile(rootPath, false); err != nil {
		t.Fatalf("writing expired root: %v", err)
	}

	err = NewTUFGenerator(testRepoConfig(t, outputDir, keyPath)).Generate()
	if err == nil {
		t.Fatal("expected Generate to fail against an expired root, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error did not mention the expired root: %v", err)
	}
	// Nothing should be published against the expired root.
	if _, statErr := os.Stat(filepath.Join(outputDir, "2.targets.json")); !os.IsNotExist(statErr) {
		t.Fatalf("2.targets.json must not exist after an expired-root update: %v", statErr)
	}
}

func TestGenerateWithoutSigningKeyRegenerates(t *testing.T) {
	outputDir := t.TempDir()

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, "")).Generate(); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	rootBefore := rootKeyIDs(t, outputDir)

	if err := NewTUFGenerator(testRepoConfig(t, outputDir, "")).Generate(); err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if got := timestampVersion(t, outputDir); got != 1 {
		t.Fatalf("without a persistent key, timestamp version = %d, want 1 (fresh repo each run)", got)
	}
	if rootAfter := rootKeyIDs(t, outputDir); rootAfter == rootBefore {
		t.Fatalf("expected a fresh root key without -signing-key, got the same: %s", rootBefore)
	}
}
