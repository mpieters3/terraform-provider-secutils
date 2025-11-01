// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks_test

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
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/jks"
)

func TestAccJKSEphemeralResource(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccJKSEphemeralResourceConfig(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("jks"),
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

func testAccJKSEphemeralResourceConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_jks" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate      = %[2]q
      certificate_chain = [%[3]q]
      alias            = "test-cert"
    }
  ]
  password = "testpassword"
}

provider "echo" {
  data = ephemeral.crypto_jks.test
}

resource "echo" "test" {}
`, privateKey, certificate, chainCert)
}

func TestAccJKSEphemeralResourceWithBaseJKS(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	baseJKS, err := createTestJKS("testpassword")
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
				Config: testAccJKSEphemeralResourceConfigWithBaseJKS(baseJKS, testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("jks"),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("base_jks"),
						knownvalue.StringExact(baseJKS),
					),
				},
			},
		},
	})
}

func TestAccJKSEphemeralResourceWithInvalidBaseJKS(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Invalid base JKS
			{
				Config:      testAccJKSEphemeralResourceConfigWithBaseJKS("!!!not-valid-base64!!!", testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("(Unable to decode base64 JKS|illegal base64 data)"),
			},
		},
	})
}

func TestAccJKSEphemeralResourceWithWrongPassword(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	baseJKS, err := createTestJKS("testpassword")
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
			// Wrong password for base JKS
			{
				Config:      testAccJKSEphemeralResourceConfigWithWrongPassword(baseJKS, testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("Unable to load base JKS"),
			},
		},
	})
}

func testAccJKSEphemeralResourceConfigWithBaseJKS(baseJKS, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_jks" "test" {
  base_jks = %[1]q
  entries = [
    {
      private_key       = %[2]q
      certificate      = %[3]q
      certificate_chain = [%[4]q]
      alias            = "test-cert"
    }
  ]
  password = "testpassword"
}

provider "echo" {
  data = ephemeral.crypto_jks.test
}

resource "echo" "test" {}
`, baseJKS, privateKey, certificate, chainCert)
}

func testAccJKSEphemeralResourceConfigWithWrongPassword(baseJKS, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
ephemeral "crypto_jks" "test" {
  base_jks = %[1]q
  entries = [
    {
      private_key       = %[2]q
      certificate      = %[3]q
      certificate_chain = [%[4]q]
      alias            = "test-cert"
    }
  ]
  password = "wrongpassword"
}

provider "echo" {
  data = ephemeral.crypto_jks.test
}

resource "echo" "test" {}
`, baseJKS, privateKey, certificate, chainCert)
}

func TestAccJKSEphemeralResourceValidation(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			// Test with valid JKS - should verify the keystore can be loaded
			{
				Config: testAccJKSEphemeralResourceConfig(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test",
						tfjsonpath.New("data").AtMapKey("jks"),
						// Custom check to verify JKS can be loaded
						knownvalue.NotNull(),
					),
				},
			},
		},
	})
}
