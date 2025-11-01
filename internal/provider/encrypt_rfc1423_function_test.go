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

func TestEncryptRFC1423Function_RoundTrip(t *testing.T) {
	_, unencryptedPEM := generateRFC1423KeyPair(t, "test")

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
					value = provider::crypto::unencrypt_rfc1423(
						provider::crypto::encrypt_rfc1423(var.unencrypted_pem, "mypassword"),
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

func TestEncryptRFC1423Function_InvalidPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::crypto::encrypt_rfc1423("invalid pem", "test")
				}
				`,
				ExpectError: regexp.MustCompile("(?s)failed:.Unable.to.decode.private.key.into.a.block"),
			},
		},
	})
}
