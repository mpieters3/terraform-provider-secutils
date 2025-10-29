// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/youmark/pkcs8"
)

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

func TestUnencryptPKCS8Function_Known(t *testing.T) {
	encryptedPEM, expectedPEM := generatePKCS8TestKeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				variable "encrypted_pem" {
					type = string
				}

				output "test" {
					value = provider::cryptoutils::unencrypt_pkcs8(var.encrypted_pem, "test")
				}
				`,
				ConfigVariables: config.Variables{
					"encrypted_pem": config.StringVariable(encryptedPEM),
				},
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

func TestUnencryptPKCS8Function_InvalidPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::cryptoutils::unencrypt_pkcs8("invalid pem", "test")
				}
				`,
				ExpectError: regexp.MustCompile("(?s)failed:.Unable.to.decode.private.key.into.a.block"),
			},
		},
	})
}

func TestUnencryptPKCS8Function_WrongPassword(t *testing.T) {
	encryptedPEM, _ := generatePKCS8TestKeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				variable "encrypted_pem" {
					type = string
				}

				output "test" {
					value = provider::cryptoutils::unencrypt_pkcs8(
						var.encrypted_pem,
						"wrongpassword"
					)
				}
				`,
				ConfigVariables: config.Variables{
					"encrypted_pem": config.StringVariable(encryptedPEM),
				},
				ExpectError: regexp.MustCompile("(?s)Failed.to.decrypt.private.key:.pkcs8:.incorrect.password"),
			},
		},
	})
}
