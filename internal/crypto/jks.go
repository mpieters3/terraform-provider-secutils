package crypto

import (
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func LoadKeyStore(jksPath string, jksPassword []byte) (*keystore.KeyStore, error) {
	// Load the keystore from the provided JKS string
	ks := keystore.New()
	f, err := os.Open(jksPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JKS file: %w", err)
	}
	defer f.Close()

	err = ks.Load(f, jksPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %w", err)
	}
	return &ks, nil
}

// Extracts the private key and its certificate chain to PEM blocks
// Parameters:
//   - ks: the loaded keystore
//   - alias: the alias of the certificate/key entry to extract
//   - keyPassword: password to unlock the specific key entry
//
// Returns:
//   - *pem.Block: PEM block containing the private key
//   - []*pem.Block: slice of PEM blocks containing the certificate chain
//   - error: any error that occurred during conversion
func JKSAliasToPEM(ks *keystore.KeyStore, alias string, keyPassword []byte) (*KeyCertChain, error) {
	// Try to get the private key entry first
	if ks.IsPrivateKeyEntry(alias) {
		privKeyEntry, err := ks.GetPrivateKeyEntry(alias, keyPassword)
		if err != nil {
			return nil, fmt.Errorf("no valid entry found for alias %s: %w", alias, err)
		}
		// Write the private key in PKCS8 format
		privateKeyBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyEntry.PrivateKey,
		}

		pemChain := []*pem.Block{}
		// Write the certificate chain if one exists
		for _, cert := range privKeyEntry.CertificateChain {
			pemChain = append(pemChain, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Content,
			})
		}
		return &KeyCertChain{
			PrivateKey: privateKeyBlock,

			PublicKey: pemChain[0],
			CertChain: pemChain[1:],
		}, nil
	} else if ks.IsTrustedCertificateEntry(alias) {
		certEntry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			return nil, fmt.Errorf("no valid entry found for alias %s: %w", alias, err)
		}
		// Write the trusted certificate
		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certEntry.Certificate.Content,
		}
		return &KeyCertChain{
			PublicKey: certBlock,
		}, nil
	}
	return nil, fmt.Errorf("no valid entry found for alias %s", alias)
}

// Extracts all entries from the keystore to PEM format
// Parameters:
//   - ks: the loaded keystore
//   - jksPassword: password to unlock the JKS file. Assumes all private keys use the same password.
//
// Returns:
//   - [][]*pem.Block: slice of slices of PEM blocks containing all entries. Each inner slice corresponds to one entry (private key + cert chain or trusted cert).
//   - error: any error that occurred during conversion
func FullJKSToPEM(ks *keystore.KeyStore, jksPassword []byte) ([]*KeyCertChain, error) {
	var pemBlocks []*KeyCertChain

	for _, alias := range ks.Aliases() {
		keyCertChain, err := JKSAliasToPEM(ks, alias, jksPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to convert entry for alias %s: %w", alias, err)
		}
		pemBlocks = append(pemBlocks, keyCertChain)
	}

	return pemBlocks, nil
}

// convertToKeystoreCert converts a PEM block to a keystore Certificate.
func convertToKeystoreCert(block *pem.Block) keystore.Certificate {
	//TODO: Support other types
	return keystore.Certificate{
		Type:    "X509",
		Content: block.Bytes,
	}
}

// Adds a KeyCertChain data to a Java KeyStore (JKS)
// Parameters:
//   - pemData: Data to add
//   - ks: the keystore to add the data to
//   - password: password to protect the JKS file
//   - alias: the alias to use for the entry in the keystore
//
// Returns:
//   - error: any error that occurred during conversion
func AddPEMToJKS(pemData *KeyCertChain, ks *keystore.KeyStore, password []byte, alias string) error {
	// Create a new keystore

	if alias == "" {
		alias = pemData.GenerateId()
	}

	currentTime := time.Now()

	// Create the appropriate entry based on the content
	if pemData.IsKeyPair() {
		certChain := []keystore.Certificate{}
		for _, certBlock := range append([]*pem.Block{pemData.PublicKey}, pemData.CertChain...) {
			certChain = append(certChain, convertToKeystoreCert(certBlock))
		}

		err := ks.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
			CreationTime:     currentTime,
			PrivateKey:       pemData.PrivateKey.Bytes,
			CertificateChain: certChain,
		}, password)
		if err != nil {
			return fmt.Errorf("failed to set private key entry: %w", err)
		}
	} else {
		err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: currentTime,
			Certificate:  convertToKeystoreCert(pemData.PublicKey),
		})
		if err != nil {
			return fmt.Errorf("failed to set trusted certificate entry: %w", err)
		}
	}

	return nil
}
