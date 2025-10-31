// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/pem"
	"os"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestAddPEMToJKS_PrivateKeyAndCert(t *testing.T) {
	ks := keystore.New()

	priv := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("privkey-bytes")}
	pub := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("cert1")}
	chain := []*pem.Block{{Type: "CERTIFICATE", Bytes: []byte("cert2")}}

	kcc := &KeyCertChain{PrivateKey: priv, PublicKey: pub, CertChain: chain}

	alias := "alias1"
	if err := AddPEMToJKS(kcc, &ks, []byte("pw"), alias); err != nil {
		t.Fatalf("AddPEMToJKS failed: %v", err)
	}

	if !ks.IsPrivateKeyEntry(alias) {
		t.Fatalf("expected alias %s to be a private key entry", alias)
	}

	entry, err := ks.GetPrivateKeyEntry(alias, []byte("pw"))
	if err != nil {
		t.Fatalf("GetPrivateKeyEntry error: %v", err)
	}

	if string(entry.PrivateKey) != string(priv.Bytes) {
		t.Fatalf("private key mismatch: got %v want %v", entry.PrivateKey, priv.Bytes)
	}

	if len(entry.CertificateChain) != 2 {
		t.Fatalf("expected certificate chain length 2, got %d", len(entry.CertificateChain))
	}
	if string(entry.CertificateChain[0].Content) != string(pub.Bytes) {
		t.Fatalf("certificate chain[0] mismatch")
	}
	if string(entry.CertificateChain[1].Content) != string(chain[0].Bytes) {
		t.Fatalf("certificate chain[1] mismatch")
	}

	// Now test JKSAliasToPEM for this alias
	got, err := JKSAliasToPEM(&ks, alias, []byte("pw"))
	if err != nil {
		t.Fatalf("JKSAliasToPEM returned error: %v", err)
	}
	if got.PrivateKey == nil || got.PublicKey == nil {
		t.Fatalf("JKSAliasToPEM did not return key pair")
	}
	if string(got.PrivateKey.Bytes) != string(priv.Bytes) {
		t.Fatalf("JKSAliasToPEM private key mismatch")
	}
	if string(got.PublicKey.Bytes) != string(pub.Bytes) {
		t.Fatalf("JKSAliasToPEM public key mismatch")
	}
	if len(got.CertChain) != 1 || string(got.CertChain[0].Bytes) != string(chain[0].Bytes) {
		t.Fatalf("JKSAliasToPEM cert chain mismatch")
	}
}

func TestAddPEMToJKS_TrustedCertAndJKSAliasToPEM(t *testing.T) {
	ks := keystore.New()

	pub := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("trusted-cert")}
	kcc := &KeyCertChain{PublicKey: pub}

	alias := "trusted1"
	if err := AddPEMToJKS(kcc, &ks, []byte("pw"), alias); err != nil {
		t.Fatalf("AddPEMToJKS (trusted) failed: %v", err)
	}

	if !ks.IsTrustedCertificateEntry(alias) {
		t.Fatalf("expected alias %s to be a trusted certificate entry", alias)
	}

	entry, err := ks.GetTrustedCertificateEntry(alias)
	if err != nil {
		t.Fatalf("GetTrustedCertificateEntry error: %v", err)
	}
	if string(entry.Certificate.Content) != string(pub.Bytes) {
		t.Fatalf("trusted certificate content mismatch")
	}

	// JKSAliasToPEM should return a KeyCertChain with only PublicKey set
	got, err := JKSAliasToPEM(&ks, alias, nil)
	if err != nil {
		t.Fatalf("JKSAliasToPEM (trusted) error: %v", err)
	}
	// Expect PublicKey present and PrivateKey nil
	if got.PublicKey == nil || got.PrivateKey != nil {
		t.Fatalf("unexpected JKSAliasToPEM result for trusted cert: public=%v private=%v", got.PublicKey, got.PrivateKey)
	}
}

func TestJKSAliasToPEM_NoEntry(t *testing.T) {
	ks := keystore.New()
	if _, err := JKSAliasToPEM(&ks, "does-not-exist", nil); err == nil {
		t.Fatalf("expected error for non-existent alias")
	}
}

func TestFullJKSToPEM(t *testing.T) {
	ks := keystore.New()

	// Add a trusted cert
	pub := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("trusted-cert-2")}
	if err := AddPEMToJKS(&KeyCertChain{PublicKey: pub}, &ks, nil, "trusted-2"); err != nil {
		t.Fatalf("AddPEMToJKS trusted failed: %v", err)
	}

	// Add a key pair
	priv := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("priv2")}
	pub2 := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("certA")}
	if err := AddPEMToJKS(&KeyCertChain{PrivateKey: priv, PublicKey: pub2}, &ks, []byte("pw"), "kp-1"); err != nil {
		t.Fatalf("AddPEMToJKS keypair failed: %v", err)
	}

	all, err := FullJKSToPEM(&ks, []byte("pw"))
	if err != nil {
		t.Fatalf("FullJKSToPEM error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 entries from FullJKSToPEM, got %d", len(all))
	}
	// check that each returned entry is either keypair or cert-only
	foundKeypair := false
	foundCert := false
	for _, e := range all {
		if e.IsKeyPair() {
			foundKeypair = true
		}
		if e.IsCertOnly() {
			foundCert = true
		}
	}
	if !foundKeypair || !foundCert {
		t.Fatalf("FullJKSToPEM did not return both keypair and cert-only entries")
	}
}

func TestLoadKeyStore(t *testing.T) {
	ks := keystore.New()

	// add a trusted cert so the stored jks isn't empty
	pub := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("on-disk-cert")}
	if err := AddPEMToJKS(&KeyCertChain{PublicKey: pub}, &ks, nil, "ondisk"); err != nil {
		t.Fatalf("AddPEMToJKS for on-disk failed: %v", err)
	}

	// write the keystore to a temp file
	tmpf, err := os.CreateTemp(t.TempDir(), "test-*.jks")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// ensure close
	tmpf.Close()

	// Store the keystore to the file using the keystore lib
	f, err := os.OpenFile(tmpf.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open for write failed: %v", err)
	}
	if err := ks.Store(f, nil); err != nil {
		f.Close()
		t.Fatalf("failed to store keystore: %v", err)
	}
	f.Close()

	// Now load using our LoadKeyStore wrapper
	loaded, err := LoadKeyStore(tmpf.Name(), nil)
	if err != nil {
		t.Fatalf("LoadKeyStore failed: %v", err)
	}
	if !loaded.IsTrustedCertificateEntry("ondisk") {
		t.Fatalf("loaded keystore missing expected entry")
	}
}
