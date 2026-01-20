// Package main provides a utility for generating TUF repositories for Sigstore testing.
//
// This tool allows developers to quickly create test TUF repositories with various
// Sigstore service configurations, mixing local services with public ones as needed
// for development and testing scenarios.
//
// WARNING: This tool is for development and testing only. Do not use in production.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func getTufClient(tufRepo string) (*tuf.Client, error) {
	switch tufRepo {
	case "default":
		return tuf.DefaultClient()
	case "staging":
		options := tuf.DefaultOptions().WithRoot(tuf.StagingRoot()).WithRepositoryBaseURL(tuf.StagingMirror)
		return tuf.New(options)
	default:
		return nil, fmt.Errorf("invalid base tuf repository: %s", tufRepo)
	}
}

func getDefaultFulcioFlags(trustedRoot *root.TrustedRoot) []string {
	fulcioFlags := []string{}
	for _, ca := range trustedRoot.FulcioCertificateAuthorities() {
		fulcioCA, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			log.Fatalf("Unexpected certificate authority type: %T", ca)
		}

		fulcioFlag := fmt.Sprintf("url=%s,start-time=%s,end-time=%s",
			fulcioCA.URI,
			fulcioCA.ValidityPeriodStart.Format(time.RFC3339),
			fulcioCA.ValidityPeriodEnd.Format(time.RFC3339),
		)
		fulcioFlags = append(fulcioFlags, fulcioFlag)
	}
	return fulcioFlags
}

func getDefaultCTFEFlags(trustedRoot *root.TrustedRoot) []string {
	ctfeFlags := []string{}
	for _, log := range trustedRoot.CTLogs() {
		ctfeFlag := fmt.Sprintf("url=%s,start-time=%s,end-time=%s",
			log.BaseURL,
			log.ValidityPeriodStart.Format(time.RFC3339),
			log.ValidityPeriodEnd.Format(time.RFC3339),
		)
		ctfeFlags = append(ctfeFlags, ctfeFlag)
	}
	return ctfeFlags
}

func getDefaultTSAFlags(trustedRoot *root.TrustedRoot) []string {
	tsaFlags := []string{}
	for _, ca := range trustedRoot.TimestampingAuthorities() {
		tsaCA, ok := ca.(*root.SigstoreTimestampingAuthority)
		if !ok {
			log.Fatalf("Unexpected timestamping authority type: %T", ca)
		}

		tsaFlag := fmt.Sprintf("url=%s,start-time=%s,end-time=%s",
			tsaCA.URI,
			tsaCA.ValidityPeriodStart.Format(time.RFC3339),
			tsaCA.ValidityPeriodEnd.Format(time.RFC3339),
		)
		tsaFlags = append(tsaFlags, tsaFlag)
	}
	return tsaFlags
}

func getRekorService(signingConfig *root.SigningConfig, baseURL string) *root.Service {
	for _, service := range signingConfig.RekorLogURLs() {
		if service.URL == baseURL {
			return &service
		}
	}
	return nil
}

func getDefaultRekorFlags(trustedRoot *root.TrustedRoot, signingConfig *root.SigningConfig, baseTempDir string) []string {
	rekorFlags := []string{}
	for _, log := range trustedRoot.RekorLogs() {
		service := getRekorService(signingConfig, log.BaseURL)
		if service == nil {
			continue
		}
		apiVersion := 1
		if service != nil {
			apiVersion = int(service.MajorAPIVersion)
		}

		extraFlag := ""
		if apiVersion == 2 {
			// rekor v2 does not provide an API to retrieve the public key
			// directly, so we take it from TUF
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(log.PublicKey)
			if err != nil {
				continue
			}
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			})
			pubKeyFile := fmt.Sprintf("%s/rekor-%x.pem", baseTempDir, sha256.Sum256(pubKeyBytes))
			if err := os.WriteFile(pubKeyFile, pubKeyPEM, 0644); err != nil {
				continue
			}
			extraFlag = fmt.Sprintf(",public-key=%s", pubKeyFile)
		}

		rekorFlag := fmt.Sprintf("url=%s,start-time=%s,end-time=%s,api-version=%d%s",
			log.BaseURL,
			log.ValidityPeriodStart.Format(time.RFC3339),
			log.ValidityPeriodEnd.Format(time.RFC3339),
			apiVersion,
			extraFlag,
		)
		rekorFlags = append(rekorFlags, rekorFlag)
	}
	return rekorFlags
}

func getDefaultOIDCFlags() []string {
	return []string{"url=https://oauth2.sigstore.dev/auth"}
}

func main() {
	tufRepo := flag.String("base-tuf", "default", "base tuf repository to use for unspecified services ('default' or 'staging')")

	var fulcioFlags []string
	flag.Func("fulcio", "fulcio service specification, as a comma-separated key-value list.\nRequired keys: url. Optional keys: certificate-chain (path to PEM-encoded certificate chain), start-time, end-time.", func(s string) error {
		fulcioFlags = append(fulcioFlags, s)
		return nil
	})
	var ctfeFlags []string
	flag.Func("ctfe", "ctfe service specification, as a comma-separated key-value list.\nRequired keys: url, public-key (path to PEM-encoded public key), start-time. Optional keys: end-time.", func(s string) error {
		ctfeFlags = append(ctfeFlags, s)
		return nil
	})
	var tsaFlags []string
	flag.Func("tsa", "timestamping authority specification, as a comma-separated key-value list.\nRequired keys: url, certificate-chain (path to PEM-encoded certificate chain). Optional keys: start-time, end-time.", func(s string) error {
		tsaFlags = append(tsaFlags, s)
		return nil
	})
	var rekorFlags []string
	flag.Func("rekor", "rekor service specification, as a comma-separated key-value list.\nRequired keys: url. Optional keys: public-key (path to PEM-encoded public key), start-time, end-time, api-version (1 default), origin.", func(s string) error {
		rekorFlags = append(rekorFlags, s)
		return nil
	})
	var oidcFlags []string
	flag.Func("oidc", "oidc provider specification, as a comma-separated key-value list.\nRequired keys: url", func(s string) error {
		oidcFlags = append(oidcFlags, s)
		return nil
	})
	outputDir := flag.String("output", "tuf-repo", "Path to the output directory")
	flag.Parse()

	tufClient, err := getTufClient(*tufRepo)
	if err != nil {
		log.Fatalf("Error creating TUF client: %v", err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatalf("Error getting trusted root: %v", err)
	}

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		log.Fatalf("Error getting signing config: %v", err)
	}

	baseTempDir, err := os.MkdirTemp("", "sigstore-tuf-simple-*")
	if err != nil {
		log.Fatalf("Error creating base temp directory: %v", err)
	}
	defer os.RemoveAll(baseTempDir)

	// Default to Sigstore services if no flags are provided
	if len(fulcioFlags) == 0 {
		fulcioFlags = getDefaultFulcioFlags(trustedRoot)
	}
	if len(ctfeFlags) == 0 {
		ctfeFlags = getDefaultCTFEFlags(trustedRoot)
	}
	if len(tsaFlags) == 0 {
		tsaFlags = getDefaultTSAFlags(trustedRoot)
	}
	if len(rekorFlags) == 0 {
		rekorFlags = getDefaultRekorFlags(trustedRoot, signingConfig, baseTempDir)
	}
	if len(oidcFlags) == 0 {
		oidcFlags = getDefaultOIDCFlags()
	}

	fmt.Fprintf(os.Stderr, "Generating TUF repository at %s...\n", *outputDir)
	fmt.Fprintf(os.Stderr, "Rekor flags: %v\n", rekorFlags)
	fmt.Fprintf(os.Stderr, "Fulcio flags: %v\n", fulcioFlags)
	fmt.Fprintf(os.Stderr, "CTFE flags: %v\n", ctfeFlags)
	fmt.Fprintf(os.Stderr, "TSA flags: %v\n", tsaFlags)
	fmt.Fprintf(os.Stderr, "OIDC flags: %v\n", oidcFlags)

	tufConfig, err := NewTUFGeneratorConfig(
		rekorFlags,
		fulcioFlags,
		ctfeFlags,
		tsaFlags,
		baseTempDir,
		*outputDir,
	)
	if err != nil {
		log.Fatalf("Error creating TUF generator config: %v", err)
	}

	generator := NewTUFGenerator(tufConfig)
	if err := generator.Generate(); err != nil {
		log.Fatalf("Error generating TUF repository: %v", err)
	}

	fmt.Println("TUF repository generated!")
}
