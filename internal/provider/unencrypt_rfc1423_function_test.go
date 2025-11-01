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

func TestUnencryptRFC1423Function_Known(t *testing.T) {
	encryptedPEM, expectedPEM := generateRFC1423KeyPair(t, "test")

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
					value = provider::crypto::unencrypt_rfc1423(var.encrypted_pem, "test")
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

func TestUnencryptRFC1423Function_InvalidPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0), // Functions were added in 1.8
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::crypto::unencrypt_rfc1423("invalid pem", "test")
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
					value = provider::crypto::unencrypt_rfc1423(var.encrypted_pem, "wrongpassword")
				}
				`,
				ConfigVariables: config.Variables{
					"encrypted_pem": config.StringVariable(encryptedPEM),
				},
				ExpectError: regexp.MustCompile("(?s)decryption.password.incorrect"),
			},
		},
	})
}
