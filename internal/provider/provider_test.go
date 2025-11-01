// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/youmark/pkcs8"
)

// Note: TestAccProtoV6ProviderFactories, TestAccProtoV6ProviderFactoriesWithEcho, and TestAccPreCheck
// are now defined in test_helpers.go (non-test file) to make them accessible from other packages' tests.

func generateRFC1423KeyPair(t *testing.T, password string) (string, string) {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert the RFC1432 encrypted DER
	//nolint:staticcheck // SA1019 we're intentionally using this weak cipher on function purpose
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(privateKey),
		[]byte(password),
		x509.PEMCipherDES, //Consider eventually doing tests of other ciphers? Unlikely to matter though
	)

	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	encryptedPEM := string(pem.EncodeToMemory(encryptedBlock))

	// Create unencrypted PEM for comparison
	//nolint:staticcheck // SA1019 we're intentionally using this weak cipher on function purpose
	unencryptedBytes, err := x509.DecryptPEMBlock(encryptedBlock, []byte(password))
	if err != nil {
		t.Fatalf("Failed to marshal unencrypted key: %v", err)
	}
	unencryptedBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: unencryptedBytes,
	}
	unencryptedPEM := string(pem.EncodeToMemory(unencryptedBlock))

	return encryptedPEM, unencryptedPEM
}

func generatePKCS8TestKeyPair(t *testing.T, password string) (string, string) {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert to PKCS8 and encrypt
	privateKeyBytes, err := pkcs8.MarshalPrivateKey(privateKey, []byte(password), nil)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Create encrypted PEM
	encryptedBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	encryptedPEM := string(pem.EncodeToMemory(encryptedBlock))

	// Create unencrypted PEM for comparison
	unencryptedBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal unencrypted key: %v", err)
	}
	unencryptedBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: unencryptedBytes,
	}
	unencryptedPEM := string(pem.EncodeToMemory(unencryptedBlock))

	return encryptedPEM, unencryptedPEM
}
