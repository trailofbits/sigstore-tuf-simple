package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestParseKVs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "valid key-value pairs",
			input:   "key1=value1,key2=value2,key3=value3",
			want:    map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			wantErr: false,
		},
		{
			name:    "single key-value pair",
			input:   "key=value",
			want:    map[string]string{"key": "value"},
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:    "whitespace handling",
			input:   " key1 = value1 , key2 = value2 ",
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "empty values",
			input:   "key1=,key2=value2",
			want:    map[string]string{"key1": "", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "empty keys",
			input:   "=value1,key2=value2",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "multiple equals signs in value",
			input:   "key1=value=with=equals,key2=value2",
			want:    map[string]string{"key1": "value=with=equals", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "comma in value",
			input:   "key1=value,with,comma,key2=value2",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   "key1=value1,key2=value2,",
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "leading comma",
			input:   ",key1=value1,key2=value2",
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "consecutive commas",
			input:   "key1=value1,,key2=value2",
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "missing equals sign",
			input:   "key1value1,key2=value2",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "key only",
			input:   "key1,key2=value2",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "value only",
			input:   "=value1,key2=value2",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "unicode characters",
			input:   "key1=value1,key2=测试,key3=value3",
			want:    map[string]string{"key1": "value1", "key2": "测试", "key3": "value3"},
			wantErr: false,
		},
		{
			name:    "special characters in key and value",
			input:   "key-1=value_1,key.2=value@2",
			want:    map[string]string{"key-1": "value_1", "key.2": "value@2"},
			wantErr: false,
		},
		{
			name:    "newlines and tabs",
			input:   "key1=value1\n,key2=value2\t,key3=value3",
			want:    map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			wantErr: false,
		},
		{
			name:    "whitespace only pairs",
			input:   "key1=value1,   ,key2=value2",
			want:    map[string]string{"key1": "value1", "key2": "value2"},
			wantErr: false,
		},
		{
			name:    "values with spaces",
			input:   "key1=value with spaces,key2=another value",
			want:    map[string]string{"key1": "value with spaces", "key2": "another value"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKVs(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKVs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseKVs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseKVsErrorMessages(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:        "missing equals sign",
			input:       "key1value1",
			expectedErr: "invalid key-value pair: key1value1",
		},
		{
			name:        "key only with comma",
			input:       "key1,key2=value2",
			expectedErr: "invalid key-value pair: key1",
		},
		{
			name:        "empty key",
			input:       "=value1,key2=value2",
			expectedErr: "empty key in key-value pair: =value1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseKVs(tt.input)
			if err == nil {
				t.Errorf("parseKVs() expected error but got none")
				return
			}
			if err.Error() != tt.expectedErr {
				t.Errorf("parseKVs() error = %v, want %v", err.Error(), tt.expectedErr)
			}
		})
	}
}

func createTestCertificate(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "test-cert",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if parent == nil {
		parent = template
		parentKey = privateKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

func writeCertificateToFile(t *testing.T, cert *x509.Certificate, filename string) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	err := os.WriteFile(filename, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}
}

func writeCertificateChainToFile(t *testing.T, certs []*x509.Certificate, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create certificate chain file: %v", err)
	}
	defer file.Close()

	for _, cert := range certs {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		_, err := file.Write(certPEM)
		if err != nil {
			t.Fatalf("Failed to write certificate to chain file: %v", err)
		}
	}
}

func TestParseFulcioSpec(t *testing.T) {
	// Create test certificates
	rootCert, rootKey := createTestCertificate(t, true, nil, nil)
	intermediateCert, intermediateKey := createTestCertificate(t, true, rootCert, rootKey)
	leafCert, _ := createTestCertificate(t, false, intermediateCert, intermediateKey)

	// Create temporary files for certificates
	tempDir := t.TempDir()
	rootCertFile := filepath.Join(tempDir, "root.pem")
	intermediateCertFile := filepath.Join(tempDir, "intermediate.pem")
	leafCertFile := filepath.Join(tempDir, "leaf.pem")
	certChainFile := filepath.Join(tempDir, "chain.pem")

	writeCertificateToFile(t, rootCert, rootCertFile)
	writeCertificateToFile(t, intermediateCert, intermediateCertFile)
	writeCertificateToFile(t, leafCert, leafCertFile)
	writeCertificateChainToFile(t, []*x509.Certificate{leafCert, intermediateCert, rootCert}, certChainFile)

	// Create test server for HTTP certificate fetching
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/rootCert" {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			// Return PEM format instead of raw bytes
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rootCert.Raw,
			})
			w.Write(certPEM)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		spec    string
		want    *root.FulcioCertificateAuthority
		wantErr bool
	}{
		{
			name: "valid spec with certificate-chain",
			spec: fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s", certChainFile),
			want: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{leafCert, intermediateCert},
				ValidityPeriodStart: rootCert.NotBefore,
				ValidityPeriodEnd:   time.Time{},
				URI:                 "https://fulcio.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid spec with URL certificate fetching",
			spec: fmt.Sprintf("url=%s", server.URL),
			want: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{},
				ValidityPeriodStart: rootCert.NotBefore,
				ValidityPeriodEnd:   time.Time{},
				URI:                 server.URL,
			},
			wantErr: false,
		},
		{
			name: "valid spec with custom start and end times",
			spec: fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,start-time=2023-01-01T00:00:00Z,end-time=2023-12-31T23:59:59Z", certChainFile),
			want: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{leafCert, intermediateCert},
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
				URI:                 "https://fulcio.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid spec with only start time",
			spec: fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,start-time=2023-01-01T00:00:00Z", certChainFile),
			want: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{leafCert, intermediateCert},
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Time{},
				URI:                 "https://fulcio.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid spec with only end time",
			spec: fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,end-time=2023-12-31T23:59:59Z", certChainFile),
			want: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{leafCert, intermediateCert},
				ValidityPeriodStart: rootCert.NotBefore,
				ValidityPeriodEnd:   time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
				URI:                 "https://fulcio.example.com",
			},
			wantErr: false,
		},
		{
			name:    "missing url",
			spec:    fmt.Sprintf("certificate-chain=%s", certChainFile),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty url",
			spec:    fmt.Sprintf("url=,certificate-chain=%s", certChainFile),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid key-value format",
			spec:    "url=https://fulcio.example.com invalid",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid certificate chain file",
			spec:    "url=https://fulcio.example.com,certificate-chain=/nonexistent/file.pem",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid start time format",
			spec:    fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,start-time=invalid-time", certChainFile),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid end time format",
			spec:    fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,end-time=invalid-time", certChainFile),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "HTTP server error",
			spec:    "url=https://nonexistent-server.example.com",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFulcioSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFulcioSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Compare the returned FulcioCertificateAuthority
			fulcioCA, ok := got.(*root.FulcioCertificateAuthority)
			if !ok {
				t.Errorf("parseFulcioSpec() returned wrong type: %T", got)
				return
			}

			// Compare basic fields
			if fulcioCA.URI != tt.want.URI {
				t.Errorf("parseFulcioSpec() URI = %v, want %v", fulcioCA.URI, tt.want.URI)
			}

			if !fulcioCA.ValidityPeriodStart.Equal(tt.want.ValidityPeriodStart) {
				t.Errorf("parseFulcioSpec() ValidityPeriodStart = %v, want %v", fulcioCA.ValidityPeriodStart, tt.want.ValidityPeriodStart)
			}

			if !fulcioCA.ValidityPeriodEnd.Equal(tt.want.ValidityPeriodEnd) {
				t.Errorf("parseFulcioSpec() ValidityPeriodEnd = %v, want %v", fulcioCA.ValidityPeriodEnd, tt.want.ValidityPeriodEnd)
			}

			// Compare certificates (just check they exist and have the right number)
			if fulcioCA.Root == nil {
				t.Errorf("parseFulcioSpec() Root certificate is nil")
			}

			if len(fulcioCA.Intermediates) != len(tt.want.Intermediates) {
				t.Errorf("parseFulcioSpec() Intermediates count = %d, want %d", len(fulcioCA.Intermediates), len(tt.want.Intermediates))
			}
		})
	}
}

func TestParseFulcioSpecErrorMessages(t *testing.T) {
	// Create test certificate
	rootCert, _ := createTestCertificate(t, true, nil, nil)
	tempDir := t.TempDir()
	certChainFile := filepath.Join(tempDir, "chain.pem")
	writeCertificateToFile(t, rootCert, certChainFile)

	tests := []struct {
		name        string
		spec        string
		expectedErr string
	}{
		{
			name:        "missing url",
			spec:        fmt.Sprintf("certificate-chain=%s", certChainFile),
			expectedErr: "missing or empty required key 'url' in fulcio spec",
		},
		{
			name:        "empty url",
			spec:        fmt.Sprintf("url=,certificate-chain=%s", certChainFile),
			expectedErr: "missing or empty required key 'url' in fulcio spec",
		},
		{
			name:        "invalid certificate chain",
			spec:        "url=https://fulcio.example.com,certificate-chain=/nonexistent/file.pem",
			expectedErr: "failed to decode certificate-chain:",
		},
		{
			name:        "invalid start time",
			spec:        fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,start-time=invalid-time", certChainFile),
			expectedErr: "parsing start-time:",
		},
		{
			name:        "invalid end time",
			spec:        fmt.Sprintf("url=https://fulcio.example.com,certificate-chain=%s,end-time=invalid-time", certChainFile),
			expectedErr: "parsing end-time:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFulcioSpec(tt.spec)
			if err == nil {
				t.Errorf("parseFulcioSpec() expected error but got none")
				return
			}
			if !strings.Contains(err.Error(), strings.TrimSuffix(tt.expectedErr, ":")) {
				t.Errorf("parseFulcioSpec() error = %v, want to contain %v", err.Error(), tt.expectedErr)
			}
		})
	}
}

func createTestPublicKey(t *testing.T) (*rsa.PublicKey, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	return &privateKey.PublicKey, privateKey
}

func writePublicKeyToFile(t *testing.T, pubKey *rsa.PublicKey, filename string) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	err = os.WriteFile(filename, pubKeyPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write public key file: %v", err)
	}
}

func TestParseRekorLog(t *testing.T) {
	// Create test public keys
	pubKey1, _ := createTestPublicKey(t)
	pubKey2, _ := createTestPublicKey(t) // Different key for testing

	// Create temporary files for public keys
	tempDir := t.TempDir()
	pubKeyFile1 := filepath.Join(tempDir, "public1.pem")
	pubKeyFile2 := filepath.Join(tempDir, "public2.pem")
	writePublicKeyToFile(t, pubKey1, pubKeyFile1)
	writePublicKeyToFile(t, pubKey2, pubKeyFile2)

	// Track HTTP requests to verify correct endpoint is called
	var requestedURLs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURLs = append(requestedURLs, r.URL.String())
		if r.URL.Path == "/api/v1/log/publicKey" {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey1)
			if err != nil {
				http.Error(w, "Failed to marshal public key", http.StatusInternalServerError)
				return
			}
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			})
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(pubKeyPEM)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Calculate expected key IDs
	expectedKeyID1, err := GetTransparencyLogID(pubKey1)
	if err != nil {
		t.Fatalf("Failed to calculate key ID 1: %v", err)
	}
	expectedKeyID2, err := GetTransparencyLogID(pubKey2)
	if err != nil {
		t.Fatalf("Failed to calculate key ID 2: %v", err)
	}

	tests := []struct {
		name         string
		spec         string
		publicKeyURL string
		want         *root.TransparencyLog
		wantID       string
		wantErr      bool
		expectedURLs []string
	}{
		{
			name:         "valid spec with local public key file",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile1),
			publicKeyURL: "",
			want: &root.TransparencyLog{
				BaseURL:             "https://rekor.example.com",
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey1,
				SignatureHashFunc:   crypto.SHA256, // RSA key defaults to SHA256
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Time{}, // Will be set to default (100 days from now)
			},
			wantID:       expectedKeyID1,
			wantErr:      false,
			expectedURLs: []string{},
		},
		{
			name:         "valid spec with API version 2",
			spec:         fmt.Sprintf("url=https://rekor.example.com,api-version=2,start-time=2023-01-01T00:00:00Z,public-key=%s", pubKeyFile1),
			publicKeyURL: "",
			want: &root.TransparencyLog{
				BaseURL:             "https://rekor.example.com",
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey1,
				SignatureHashFunc:   crypto.SHA256, // RSA key defaults to SHA256
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Time{}, // Will be set to default (100 days from now)
			},
			wantID:       "1783550058", // Numeric ID for API version 2 (actual generated value)
			wantErr:      false,
			expectedURLs: []string{},
		},
		{
			name:         "valid spec with URL public key fetching (Rekor)",
			spec:         fmt.Sprintf("url=%s,start-time=2023-01-01T00:00:00Z", server.URL),
			publicKeyURL: "/api/v1/log/publicKey",
			want: &root.TransparencyLog{
				BaseURL:             server.URL,
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey1,
				SignatureHashFunc:   crypto.SHA256,
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Time{}, // Will be set to default (100 days from now)
			},
			wantID:       expectedKeyID1,
			wantErr:      false,
			expectedURLs: []string{"/api/v1/log/publicKey"},
		},
		{
			name:         "valid spec with custom start and end times",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z,end-time=2023-12-31T23:59:59Z", pubKeyFile1),
			publicKeyURL: "",
			want: &root.TransparencyLog{
				BaseURL:             "https://rekor.example.com",
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey1,
				SignatureHashFunc:   crypto.SHA256,
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			wantID:       expectedKeyID1,
			wantErr:      false,
			expectedURLs: []string{},
		},
		{
			name:         "valid spec with only end time",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z,end-time=2023-12-31T23:59:59Z", pubKeyFile1),
			publicKeyURL: "",
			want: &root.TransparencyLog{
				BaseURL:             "https://rekor.example.com",
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey1,
				SignatureHashFunc:   crypto.SHA256,
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			wantID:       expectedKeyID1,
			wantErr:      false,
			expectedURLs: []string{},
		},
		{
			name:         "missing url",
			spec:         fmt.Sprintf("public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile1),
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "empty url",
			spec:         fmt.Sprintf("url=,public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile1),
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "invalid key-value format",
			spec:         "url=https://rekor.example.com invalid",
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "invalid public key file",
			spec:         "url=https://rekor.example.com,public-key=/nonexistent/file.pem,start-time=2023-01-01T00:00:00Z",
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "missing public-key and public-key-url",
			spec:         "url=https://rekor.example.com,start-time=2023-01-01T00:00:00Z",
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "invalid start time format",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=invalid-time", pubKeyFile1),
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "invalid end time format",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z,end-time=invalid-time", pubKeyFile1),
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "valid spec with different public key",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile2),
			publicKeyURL: "",
			want: &root.TransparencyLog{
				BaseURL:             "https://rekor.example.com",
				HashFunc:            crypto.SHA256,
				PublicKey:           pubKey2,
				SignatureHashFunc:   crypto.SHA256,
				ValidityPeriodStart: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ValidityPeriodEnd:   time.Time{}, // Will be set to default (100 days from now)
			},
			wantID:       expectedKeyID2,
			wantErr:      false,
			expectedURLs: []string{},
		},
		{
			name:         "HTTP server error for public key",
			spec:         "url=https://nonexistent-server.example.com,start-time=2023-01-01T00:00:00Z",
			publicKeyURL: "/api/v1/log/publicKey",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
		{
			name:         "rekor v2 without public-key should fail",
			spec:         "url=https://rekor.example.com,api-version=2",
			publicKeyURL: "",
			want:         nil,
			wantID:       "",
			wantErr:      true,
			expectedURLs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset requested URLs for each test
			requestedURLs = []string{}

			got, gotID, err := parseRekorLog(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRekorLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify the returned TransparencyLog
			if got == nil {
				t.Errorf("parseRekorLog() returned nil TransparencyLog")
				return
			}

			// Compare basic fields
			if got.BaseURL != tt.want.BaseURL {
				t.Errorf("parseRekorLog() BaseURL = %v, want %v", got.BaseURL, tt.want.BaseURL)
			}

			if got.HashFunc != tt.want.HashFunc {
				t.Errorf("parseRekorLog() HashFunc = %v, want %v", got.HashFunc, tt.want.HashFunc)
			}

			if got.SignatureHashFunc != tt.want.SignatureHashFunc {
				t.Errorf("parseRekorLog() SignatureHashFunc = %v, want %v", got.SignatureHashFunc, tt.want.SignatureHashFunc)
			}

			if !got.ValidityPeriodStart.Equal(tt.want.ValidityPeriodStart) {
				t.Errorf("parseRekorLog() ValidityPeriodStart = %v, want %v", got.ValidityPeriodStart, tt.want.ValidityPeriodStart)
			}

			// For ValidityPeriodEnd, check if it's approximately 100 days from now (default behavior)
			// or if it matches the expected time exactly
			if tt.want.ValidityPeriodEnd.IsZero() {
				// If expected time is zero, check that actual time is approximately 100 days from now
				expectedEndTime := time.Now().Add(100 * 24 * time.Hour)
				timeDiff := got.ValidityPeriodEnd.Sub(expectedEndTime)
				if timeDiff < -time.Minute || timeDiff > time.Minute {
					t.Errorf("parseRekorLog() ValidityPeriodEnd = %v, expected approximately %v (within 1 minute)", got.ValidityPeriodEnd, expectedEndTime)
				}
			} else {
				// If expected time is not zero, check exact match
				if !got.ValidityPeriodEnd.Equal(tt.want.ValidityPeriodEnd) {
					t.Errorf("parseRekorLog() ValidityPeriodEnd = %v, want %v", got.ValidityPeriodEnd, tt.want.ValidityPeriodEnd)
				}
			}

			// Compare public key
			if got.PublicKey == nil {
				t.Errorf("parseRekorLog() PublicKey is nil")
			} else {
				// Compare the actual public key bytes
				gotPubKeyBytes, err := x509.MarshalPKIXPublicKey(got.PublicKey)
				if err != nil {
					t.Errorf("Failed to marshal returned public key: %v", err)
				}
				wantPubKeyBytes, err := x509.MarshalPKIXPublicKey(tt.want.PublicKey)
				if err != nil {
					t.Errorf("Failed to marshal expected public key: %v", err)
				}
				if !reflect.DeepEqual(gotPubKeyBytes, wantPubKeyBytes) {
					t.Errorf("parseRekorLog() PublicKey mismatch")
				}
			}

			// Compare ID
			// For API version 2, the ID is numeric and may vary, so we only verify it's not empty
			if got.APIVersion == 2 {
				if gotID == "" {
					t.Errorf("parseRekorLog() ID is empty for API version 2")
				}
				// Verify it's a numeric string
				if _, err := strconv.ParseUint(gotID, 10, 32); err != nil {
					t.Errorf("parseRekorLog() ID for API version 2 is not numeric: %v", gotID)
				}
			} else {
				// For API version 1, verify exact match
				if gotID != tt.wantID {
					t.Errorf("parseRekorLog() ID = %v, want %v", gotID, tt.wantID)
				}
			}

			// Verify that the ID matches the public key
			if got.PublicKey != nil {
				// For API version 1, verify against hex string
				// For API version 2, the ID is numeric and comes from note.KeyHash
				if got.APIVersion == 1 {
					calculatedID, err := GetTransparencyLogID(got.PublicKey)
					if err != nil {
						t.Errorf("Failed to calculate transparency log ID: %v", err)
					} else if calculatedID != gotID {
						t.Errorf("parseRekorLog() ID mismatch: got %v, calculated %v", gotID, calculatedID)
					}
				}
				// For API version 2, we can't easily verify the numeric ID without duplicating the note.KeyHash logic
			}

			// Verify HTTP requests if expected
			if len(tt.expectedURLs) > 0 {
				if len(requestedURLs) != len(tt.expectedURLs) {
					t.Errorf("parseRekorLog() made %d HTTP requests, want %d", len(requestedURLs), len(tt.expectedURLs))
				} else {
					for i, expectedURL := range tt.expectedURLs {
						if i < len(requestedURLs) && requestedURLs[i] != expectedURL {
							t.Errorf("parseRekorLog() HTTP request %d = %v, want %v", i, requestedURLs[i], expectedURL)
						}
					}
				}
			}
		})
	}
}

func TestParseRekorLogErrorMessages(t *testing.T) {
	// Create test public key
	pubKey, _ := createTestPublicKey(t)
	tempDir := t.TempDir()
	pubKeyFile := filepath.Join(tempDir, "public.pem")
	writePublicKeyToFile(t, pubKey, pubKeyFile)

	tests := []struct {
		name         string
		spec         string
		publicKeyURL string
		expectedErr  string
	}{
		{
			name:         "missing url",
			spec:         fmt.Sprintf("public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile),
			publicKeyURL: "",
			expectedErr:  "missing or empty required key 'url' in tlog spec",
		},
		{
			name:         "empty url",
			spec:         fmt.Sprintf("url=,public-key=%s,start-time=2023-01-01T00:00:00Z", pubKeyFile),
			publicKeyURL: "",
			expectedErr:  "missing or empty required key 'url' in tlog spec",
		},
		{
			name:         "missing public-key and public-key-url",
			spec:         "url=https://rekor.example.com,start-time=2023-01-01T00:00:00Z",
			publicKeyURL: "",
			expectedErr:  "failed to fetch public key from URL",
		},
		{
			name:         "invalid public key file",
			spec:         "url=https://rekor.example.com,public-key=/nonexistent/file.pem,start-time=2023-01-01T00:00:00Z",
			publicKeyURL: "",
			expectedErr:  "parsing public-key:",
		},
		{
			name:         "invalid start time",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=invalid-time", pubKeyFile),
			publicKeyURL: "",
			expectedErr:  "parsing start-time:",
		},
		{
			name:         "invalid end time",
			spec:         fmt.Sprintf("url=https://rekor.example.com,public-key=%s,start-time=2023-01-01T00:00:00Z,end-time=invalid-time", pubKeyFile),
			publicKeyURL: "",
			expectedErr:  "parsing end-time:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseRekorLog(tt.spec)
			if err == nil {
				t.Errorf("parseRekorLog() expected error but got none")
				return
			}
			if !strings.Contains(err.Error(), strings.TrimSuffix(tt.expectedErr, ":")) {
				t.Errorf("parseRekorLog() error = %v, want to contain %v", err.Error(), tt.expectedErr)
			}
		})
	}
}
