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

func TestEncryptPKCS8Function_RoundTrip(t *testing.T) {
	_, unencryptedPEM := generatePKCS8TestKeyPair(t, "test")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				variable "unencrypted_pem" {
					type = string
				}

				output "decrypted" {
					value = provider::crypto::unencrypt_pkcs8(
						provider::crypto::encrypt_pkcs8(var.unencrypted_pem, "mypassword"),
						"mypassword"
					)
				}
				`,
				ConfigVariables: config.Variables{
					"unencrypted_pem": config.StringVariable(unencryptedPEM),
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue(
						"decrypted",
						knownvalue.StringExact(unencryptedPEM),
					),
				},
			},
		},
	})
}

func TestEncryptPKCS8Function_InvalidPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::crypto::encrypt_pkcs8("invalid pem", "test")
				}
				`,
				ExpectError: regexp.MustCompile("(?s)failed:.Unable.to.decode.private.key.into.a.block"),
			},
		},
	})
}
