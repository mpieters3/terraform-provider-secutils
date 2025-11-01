// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestUnencryptPKCS8Function_Known(t *testing.T) {
	encryptedPEM, expectedPEM := generatePKCS8TestKeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0), // Functions were added in 1.8
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				variable "encrypted_pem" {
					type = string
				}

				output "test" {
					value = provider::crypto::unencrypt_pkcs8(var.encrypted_pem, "test")
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
			tfversion.SkipBelow(tfversion.Version1_8_0), // Functions were added in 1.8
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::crypto::unencrypt_pkcs8("invalid pem","test")
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
			tfversion.SkipBelow(tfversion.Version1_8_0), // Functions were added in 1.8
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				variable "encrypted_pem" {
					type = string
				}

				output "test" {
					value = provider::crypto::unencrypt_pkcs8(
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
