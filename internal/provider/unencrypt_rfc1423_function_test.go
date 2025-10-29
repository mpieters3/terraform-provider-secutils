// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

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

func TestUnencryptRFC1423Function_Known(t *testing.T) {
	encryptedPEM, expectedPEM := generateRFC1423KeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::cryptoutils::unencrypt_rfc1423("` + strings.ReplaceAll(encryptedPEM, "\n", "\\n") + `", "test")
				}
				`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue(
						"test",
						knownvalue.StringExact(expectedPEM),
					),
				},
			},
		},
	})
}

func TestUnencryptRFC1423Function_InvalidPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::cryptoutils::unencrypt_rfc1423("invalid pem", "test")
				}
				`,
				ExpectError: regexp.MustCompile("(?s)failed:.Unable.to.decode.private.key.into.a.block"),
			},
		},
	})
}

func TestUnencryptRFC1423Function_WrongPassword(t *testing.T) {
	encryptedPEM, _ := generateRFC1423KeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::cryptoutils::unencrypt_rfc1423("` + strings.ReplaceAll(encryptedPEM, "\n", "\\n") + `", "wrongpassword")
				}
				`,
				ExpectError: regexp.MustCompile("(?s)decryption.password.incorrect"),
			},
		},
	})
}
