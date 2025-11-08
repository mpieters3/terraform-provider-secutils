// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"crypto/x509"
	"fmt"
)

// ParsePrivateKey parses a private key from DER-encoded bytes.
// It attempts to parse the key as PKCS#8, PKCS#1 RSA, or EC private key.
func ParsePrivateKey(der []byte) (interface{}, error) {
	// Try parsing as PKCS#8
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		return key, nil
	}

	// Try parsing as PKCS#1 RSA key
	key, err = x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return key, nil
	}

	// Try parsing as EC private key
	key, err = x509.ParseECPrivateKey(der)
	if err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// MarshalPrivateKey marshals a private key to PKCS#8 DER-encoded bytes.
func MarshalPrivateKey(key interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// ParseCertificate parses an X.509 certificate from DER-encoded bytes.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
