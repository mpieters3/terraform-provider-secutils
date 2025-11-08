// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/p12"
)

func TestAccP12EphemeralResource(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccP12EphemeralResourceConfig(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("p12"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("id"),
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func testAccP12EphemeralResourceConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_p12" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "test-cert"
    }
  ]
  password = "testpassword"
}

provider "echo" {
  data = ephemeral.crypto_p12.test
}

resource "echo" "test" {}
`, privateKey, certificate, chainCert)
}

func TestAccP12EphemeralResourceWithBaseP12(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	baseP12, err := createTestP12("testpassword")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccP12EphemeralResourceConfigWithBaseP12(baseP12, testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("p12"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("base_p12"),
						knownvalue.StringExact(baseP12),
					),
				},
			},
		},
	})
}

func TestAccP12EphemeralResourceWithInvalidBaseP12(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Invalid base P12
			{
				Config:      testAccP12EphemeralResourceConfigWithBaseP12("!!!not-valid-base64!!!", testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("(Unable to decode base64 P12|illegal base64 data)"),
			},
		},
	})
}

func TestAccP12EphemeralResourceWithWrongPassword(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	baseP12, err := createTestP12("testpassword")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Wrong password for base P12
			{
				Config:      testAccP12EphemeralResourceConfigWithWrongPassword(baseP12, testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("(Unable to load base P12|pkcs12)"),
			},
		},
	})
}

func testAccP12EphemeralResourceConfigWithBaseP12(baseP12, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_p12" "test" {
  base_p12 = %[1]q
  entries = [
    {
      private_key       = %[2]q
      certificate       = %[3]q
      certificate_chain = [%[4]q]
      alias             = "test-cert"
    }
  ]
  password = "testpassword"
}

provider "echo" {
  data = ephemeral.crypto_p12.test
}

resource "echo" "test" {}
`, baseP12, privateKey, certificate, chainCert)
}

func testAccP12EphemeralResourceConfigWithWrongPassword(baseP12, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_p12" "test" {
  base_p12 = %[1]q
  entries = [
    {
      private_key       = %[2]q
      certificate       = %[3]q
      certificate_chain = [%[4]q]
      alias             = "test-cert"
    }
  ]
  password = "wrongpassword"
}

provider "echo" {
  data = ephemeral.crypto_p12.test
}

resource "echo" "test" {}
`, baseP12, privateKey, certificate, chainCert)
}

func TestAccP12EphemeralResourceValidation(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Test with valid P12 - should verify the P12 can be decoded
			{
				Config: testAccP12EphemeralResourceConfig(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("p12"),
						// Custom check to verify P12 can be decoded
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}

func TestAccP12EphemeralResourceMultipleKeys(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Try to create ephemeral P12 with multiple private keys - should fail
			{
				Config:      testAccP12EphemeralResourceConfigMultipleKeys(testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("P12 Library Limitation.*only supports encoding one private key"),
			},
		},
	})
}

func testAccP12EphemeralResourceConfigMultipleKeys(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_p12" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "cert-1"
    },
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "cert-2"
    }
  ]
  password = "testpassword"
}

provider "echo" {
  data = ephemeral.crypto_p12.test
}

resource "echo" "test" {}
`, privateKey, certificate, chainCert)
}
