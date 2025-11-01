// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/util"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// KeyCertEntry describes a single private key, certificate and chain entry.
type KeyCertEntry struct {
	PrivateKey       types.String `tfsdk:"private_key"`
	Certificate      types.String `tfsdk:"certificate"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
	Alias            types.String `tfsdk:"alias"`
}

// CertEntry describes a single certificate with an optional alias.
type CertEntry struct {
	Certificate types.String `tfsdk:"certificate"`
	Alias       types.String `tfsdk:"alias"`
}

// JKSModel describes the common data model for JKS resources, data sources, and ephemeral resources.
type JKSModel struct {
	Entries         types.List   `tfsdk:"entries"`
	Password        types.String `tfsdk:"password"`
	BaseJKS         types.String `tfsdk:"base_jks"`
	AdditionalCerts types.List   `tfsdk:"additional_certs"`
	JKS             types.String `tfsdk:"jks"`
	Id              types.String `tfsdk:"id"`
}

// hashString calculates a SHA-256 hash of the input string.
func hashString(input string) []byte {
	h := sha256.New()
	h.Write([]byte(input))
	return h.Sum(nil)
}

// decodePEMBlock decodes a PEM-encoded string into a pem.Block.
func decodePEMBlock(pemStr string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block, nil
}

// generateRandomAlias generates a random alias string for JKS entries.
func generateRandomAlias() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random alias: %w", err)
	}
	return "entry-" + hex.EncodeToString(bytes), nil
}

// createJKS handles the common logic for creating a JKS from the model data.
// This function is used by resources, data sources, and ephemeral resources.
func createJKS(ctx context.Context, data *JKSModel, diagnostics *diag.Diagnostics, operation string) {
	var ks keystore.KeyStore

	// If base JKS is provided, use it as the initial keystore
	if !data.BaseJKS.IsNull() {
		// Decode base64 JKS
		baseJKSBytes, err := base64.StdEncoding.DecodeString(data.BaseJKS.ValueString())
		if err != nil {
			diagnostics.AddError("Base JKS Error", fmt.Sprintf("Unable to decode base64 JKS: %s", err))
			return
		}

		// Load the base JKS
		ks = keystore.New()
		err = ks.Load(bytes.NewReader(baseJKSBytes), []byte(data.Password.ValueString()))
		if err != nil {
			diagnostics.AddError("Base JKS Error", fmt.Sprintf("Unable to load base JKS: %s", err))
			return
		}
	} else {
		// Create a new keystore if no base JKS is provided
		ks = keystore.New()
	}

	// Get entries from the model
	var entries []KeyCertEntry
	diagnostics.Append(data.Entries.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return
	}

	// Process each entry
	for _, entry := range entries {
		// Decode the private key
		privateKeyBlock, err := decodePEMBlock(entry.PrivateKey.ValueString())
		if err != nil {
			diagnostics.AddError("Private Key Error", fmt.Sprintf("Unable to decode private key: %s", err))
			return
		}

		// Decode the certificate
		certificateBlock, err := decodePEMBlock(entry.Certificate.ValueString())
		if err != nil {
			diagnostics.AddError("Certificate Error", fmt.Sprintf("Unable to decode certificate: %s", err))
			return
		}

		// Decode the certificate chain
		var certChain []types.String
		diagnostics.Append(entry.CertificateChain.ElementsAs(ctx, &certChain, false)...)
		if diagnostics.HasError() {
			return
		}

		var certChainBlocks []*pem.Block
		for _, certStr := range certChain {
			block, err := decodePEMBlock(certStr.ValueString())
			if err != nil {
				diagnostics.AddError("Certificate Chain Error", fmt.Sprintf("Unable to decode certificate chain: %s", err))
				return
			}
			certChainBlocks = append(certChainBlocks, block)
		}

		// Create util.KeyCertChain
		keyCertChain := &util.KeyCertChain{
			PrivateKey: privateKeyBlock,
			PublicKey:  certificateBlock,
			CertChain:  certChainBlocks,
		}

		// Determine the alias to use
		alias := entry.Alias.ValueString()
		if alias == "" {
			generatedAlias, err := generateRandomAlias()
			if err != nil {
				diagnostics.AddError("Alias Generation Error", fmt.Sprintf("Unable to generate alias: %s", err))
				return
			}
			alias = generatedAlias
			tflog.Debug(ctx, "Generated random alias for entry", map[string]any{
				"alias": alias,
			})
		}

		// Add to JKS
		err = AddPEMToJKS(keyCertChain, &ks, []byte(data.Password.ValueString()), alias)
		if err != nil {
			diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to create JKS: %s", err))
			return
		}
	}

	// Get entries for additional ca's to add
	var additionalCerts []CertEntry
	diagnostics.Append(data.AdditionalCerts.ElementsAs(ctx, &additionalCerts, false)...)
	if diagnostics.HasError() {
		return
	}

	// Process each entry
	for _, entry := range additionalCerts {
		block, err := decodePEMBlock(entry.Certificate.ValueString())
		if err != nil {
			diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to decode additional certificate: %s", err))
			return
		}

		// Create util.KeyCertChain
		keyCertChain := &util.KeyCertChain{
			PublicKey: block,
		}

		// Determine the alias to use
		alias := entry.Alias.ValueString()
		if alias == "" {
			generatedAlias, err := generateRandomAlias()
			if err != nil {
				diagnostics.AddError("Alias Generation Error", fmt.Sprintf("Unable to generate alias: %s", err))
				return
			}
			alias = generatedAlias
			tflog.Debug(ctx, "Generated random alias for additional certificate", map[string]any{
				"alias": alias,
			})
		}

		// Add to JKS
		err = AddPEMToJKS(keyCertChain, &ks, []byte(data.Password.ValueString()), alias)
		if err != nil {
			diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to add to JKS: %s", err))
			return
		}
	}

	// Store JKS in memory buffer
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(data.Password.ValueString())); err != nil {
		diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to store JKS: %s", err))
		return
	}

	// Encode JKS as base64
	jksBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	data.JKS = types.StringValue(jksBase64)

	// Generate identifier based on the content
	data.Id = types.StringValue(fmt.Sprintf("jks-%x", hashString(jksBase64)))

	// Write logs using the tflog package
	tflog.Trace(ctx, operation+" a JKS")
}

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
func JKSAliasToPEM(ks *keystore.KeyStore, alias string, keyPassword []byte) (*util.KeyCertChain, error) {
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
		return &util.KeyCertChain{
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
		return &util.KeyCertChain{
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
func FullJKSToPEM(ks *keystore.KeyStore, jksPassword []byte) ([]*util.KeyCertChain, error) {
	var pemBlocks []*util.KeyCertChain

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

// Adds a util.KeyCertChain data to a Java KeyStore (JKS)
// Parameters:
//   - pemData: Data to add
//   - ks: the keystore to add the data to
//   - password: password to protect the JKS file
//   - alias: the alias to use for the entry in the keystore
//
// Returns:
//   - error: any error that occurred during conversion
func AddPEMToJKS(pemData *util.KeyCertChain, ks *keystore.KeyStore, password []byte, alias string) error {
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
