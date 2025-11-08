// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/util"
	"software.sslmate.com/src/go-pkcs12"
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

// P12Model describes the common data model for P12 resources, data sources, and ephemeral resources.
type P12Model struct {
	Entries         types.List   `tfsdk:"entries"`
	Password        types.String `tfsdk:"password"`
	BaseP12         types.String `tfsdk:"base_p12"`
	AdditionalCerts types.List   `tfsdk:"additional_certs"`
	P12             types.String `tfsdk:"p12"`
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

// createP12 handles the common logic for creating a P12 from the model data.
// This function is used by resources, data sources, and ephemeral resources.
func createP12(ctx context.Context, data *P12Model, diagnostics *diag.Diagnostics, operation string) {
	var p12Data []byte
	var err error

	// Get entries from the model
	var entries []KeyCertEntry
	diagnostics.Append(data.Entries.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return
	}

	// Get entries for additional ca's to add
	var additionalCerts []CertEntry
	diagnostics.Append(data.AdditionalCerts.ElementsAs(ctx, &additionalCerts, false)...)
	if diagnostics.HasError() {
		return
	}

	// Note: While the PKCS#12 format supports multiple private keys, the go-pkcs12 library
	// used here only supports encoding one private key per P12 file. This is a library limitation.
	if len(entries) > 1 {
		diagnostics.AddError(
			"P12 Library Limitation",
			"The go-pkcs12 library only supports encoding one private key entry per P12 file. "+
				"While the PKCS#12 format itself supports multiple keys, this implementation is limited to one. "+
				"Please provide only one entry with a private key.",
		)
		return
	}

	// Process the single entry if it exists
	if len(entries) == 1 {
		entry := entries[0]

		// Decode the private key
		privateKeyBlock, err := decodePEMBlock(entry.PrivateKey.ValueString())
		if err != nil {
			diagnostics.AddError("Private Key Error", fmt.Sprintf("Unable to decode private key: %s", err))
			return
		}

		// Parse the private key
		privateKey, err := util.ParsePrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			diagnostics.AddError("Private Key Error", fmt.Sprintf("Unable to parse private key: %s", err))
			return
		}

		// Decode the certificate
		certificateBlock, err := decodePEMBlock(entry.Certificate.ValueString())
		if err != nil {
			diagnostics.AddError("Certificate Error", fmt.Sprintf("Unable to decode certificate: %s", err))
			return
		}

		// Parse the certificate
		certificate, err := util.ParseCertificate(certificateBlock.Bytes)
		if err != nil {
			diagnostics.AddError("Certificate Error", fmt.Sprintf("Unable to parse certificate: %s", err))
			return
		}

		// Decode the certificate chain
		var certChain []types.String
		diagnostics.Append(entry.CertificateChain.ElementsAs(ctx, &certChain, false)...)
		if diagnostics.HasError() {
			return
		}

		// Parse certificate chain
		var caCerts []*x509.Certificate
		for _, certStr := range certChain {
			block, err := decodePEMBlock(certStr.ValueString())
			if err != nil {
				diagnostics.AddError("Certificate Chain Error", fmt.Sprintf("Unable to decode certificate chain: %s", err))
				return
			}

			cert, err := util.ParseCertificate(block.Bytes)
			if err != nil {
				diagnostics.AddError("Certificate Chain Error", fmt.Sprintf("Unable to parse certificate chain: %s", err))
				return
			}
			caCerts = append(caCerts, cert)
		}

		// Add additional certificates to the CA certs
		for _, certEntry := range additionalCerts {
			block, err := decodePEMBlock(certEntry.Certificate.ValueString())
			if err != nil {
				diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to decode additional certificate: %s", err))
				return
			}

			cert, err := util.ParseCertificate(block.Bytes)
			if err != nil {
				diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to parse additional certificate: %s", err))
				return
			}
			caCerts = append(caCerts, cert)
		}

		// Encode as PKCS12 (note: caCerts is []*x509.Certificate)
		// Use Passwordless encoder if password is empty, otherwise use Modern encoder
		password := data.Password.ValueString()
		if password == "" {
			p12Data, err = pkcs12.Passwordless.Encode(privateKey, certificate, caCerts, "")
		} else {
			p12Data, err = pkcs12.Modern.Encode(privateKey, certificate, caCerts, password)
		}
		if err != nil {
			diagnostics.AddError("P12 Error", fmt.Sprintf("Unable to encode P12: %s", err))
			return
		}

	} else if len(additionalCerts) > 0 {
		// If there are no private key entries, but there are additional certs,
		// create a P12 with just the trusted certificates
		var caCerts []*x509.Certificate
		for _, certEntry := range additionalCerts {
			block, err := decodePEMBlock(certEntry.Certificate.ValueString())
			if err != nil {
				diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to decode additional certificate: %s", err))
				return
			}

			cert, err := util.ParseCertificate(block.Bytes)
			if err != nil {
				diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to parse additional certificate: %s", err))
				return
			}
			caCerts = append(caCerts, cert)
		}

		// Create a P12 with just certificates (no private key)
		// Use Passwordless encoder if password is empty, otherwise use Modern encoder
		password := data.Password.ValueString()
		if password == "" {
			p12Data, err = pkcs12.Passwordless.EncodeTrustStore(caCerts, "")
		} else {
			p12Data, err = pkcs12.Modern.EncodeTrustStore(caCerts, password)
		}
		if err != nil {
			diagnostics.AddError("P12 Error", fmt.Sprintf("Unable to encode P12: %s", err))
			return
		}
	} else {
		diagnostics.AddError("P12 Error", "Must provide at least one entry or additional certificate")
		return
	}

	// Encode P12 as base64
	p12Base64 := base64.StdEncoding.EncodeToString(p12Data)
	data.P12 = types.StringValue(p12Base64)

	// Generate identifier based on the content
	data.Id = types.StringValue(fmt.Sprintf("p12-%x", hashString(p12Base64)))

	// Write logs using the tflog package
	tflog.Trace(ctx, operation+" a P12")
}

// P12ToPEM extracts the private key and certificate chain from a P12 file to PEM format
// Parameters:
//   - p12Data: the P12 file bytes
//   - password: password to unlock the P12 file
//
// Returns:
//   - *util.KeyCertChain: the extracted key and certificate chain
//   - error: any error that occurred during conversion
func P12ToPEM(p12Data []byte, password string) (*util.KeyCertChain, error) {
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode P12: %w", err)
	}

	result := &util.KeyCertChain{}

	// Convert private key to PEM
	if privateKey != nil {
		privateKeyBytes, err := util.MarshalPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}

		result.PrivateKey = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		}
	}

	// Convert certificate to PEM
	if certificate != nil {
		result.PublicKey = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
	}

	// Convert CA certificates to PEM
	for _, caCert := range caCerts {
		result.CertChain = append(result.CertChain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})
	}

	return result, nil
}
