// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

type KeyCertChain struct {
	PrivateKey *pem.Block   // PEM block containing the private key
	PublicKey  *pem.Block   // PEM block containing the public key (certificate)
	CertChain  []*pem.Block // Slice of PEM blocks containing the certificate chain
}

func (kcc *KeyCertChain) IsKeyPair() bool {
	return kcc.PrivateKey != nil && kcc.PublicKey != nil
}
func (kcc *KeyCertChain) IsCertOnly() bool {
	return kcc.PrivateKey == nil && kcc.PublicKey != nil
}

func (kcc *KeyCertChain) GenerateId() string {
	// Create a hasher
	hasher := sha256.New()

	// Add private key bytes if present
	if kcc.PrivateKey != nil {
		hasher.Write(kcc.PrivateKey.Bytes)
	}

	// Add public key bytes if present
	if kcc.PublicKey != nil {
		hasher.Write(kcc.PublicKey.Bytes)
	}

	// Add certificate chain bytes if present
	for _, cert := range kcc.CertChain {
		hasher.Write(cert.Bytes)
	}

	// Get the hash and encode it
	hash := hasher.Sum(nil)
	// Return first 8 characters of hex-encoded hash
	if kcc.IsKeyPair() {
		return fmt.Sprintf("keypair-%s", hex.EncodeToString(hash)[:8])
	} else if kcc.IsCertOnly() {
		return fmt.Sprintf("cert-%s", hex.EncodeToString(hash)[:8])
	}

	return "empty"
}
