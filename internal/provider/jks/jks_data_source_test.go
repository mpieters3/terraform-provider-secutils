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
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/jks"
)

func TestAccJKSDataSourceRead(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Use resource to create JKS, then read it with data source
			{
				Config: testAccJKSDataSourceReadConfig(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.crypto_jks.test",
						tfjsonpath.New("id"),
						knownvalue.NotNull(),
					),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crypto_jks.test", "id"),
					// Verify we extracted entries
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.crypto_jks.test"]
						if !ok {
							return fmt.Errorf("JKS data source not found")
						}

						// Check that entries were extracted
						entriesCount := rs.Primary.Attributes["entries.#"]
						if entriesCount != "1" {
							return fmt.Errorf("expected 1 entry, got %s", entriesCount)
						}

						// Verify the alias matches what we expect (auto-generated with "entry-" prefix)
						alias := rs.Primary.Attributes["entries.0.alias"]
						if len(alias) == 0 {
							return fmt.Errorf("expected alias to be set")
						}

						// Verify we have a private key
						if rs.Primary.Attributes["entries.0.private_key"] == "" {
							return fmt.Errorf("expected private_key to be set")
						}

						// Verify we have a certificate
						if rs.Primary.Attributes["entries.0.certificate"] == "" {
							return fmt.Errorf("expected certificate to be set")
						}

						// Verify certificate chain count
						chainCount := rs.Primary.Attributes["entries.0.certificate_chain.#"]
						if chainCount != "1" {
							return fmt.Errorf("expected 1 chain certificate, got %s", chainCount)
						}

						return nil
					},
				),
			},
		},
	})
}

func TestAccJKSDataSourceReadWithAdditionalCerts(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Create JKS with both entries and additional certs, then read it
			{
				Config: testAccJKSDataSourceReadConfigWithAdditionalCerts(testPrivateKey, testCertificate, testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.crypto_jks.test",
						tfjsonpath.New("id"),
						knownvalue.NotNull(),
					),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crypto_jks.test", "id"),
					// Verify we extracted entries
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.crypto_jks.test"]
						if !ok {
							return fmt.Errorf("JKS data source not found")
						}

						// Check that entries were extracted
						entriesCount := rs.Primary.Attributes["entries.#"]
						if entriesCount != "1" {
							return fmt.Errorf("expected 1 entry, got %s", entriesCount)
						}

						// Verify we have a private key entry
						if rs.Primary.Attributes["entries.0.private_key"] == "" {
							return fmt.Errorf("expected private_key to be set")
						}

						// Check that additional_certs were extracted
						additionalCertsCount := rs.Primary.Attributes["additional_certs.#"]
						if additionalCertsCount != "1" {
							return fmt.Errorf("expected 1 additional cert, got %s", additionalCertsCount)
						}

						// Verify the additional cert has required fields
						if rs.Primary.Attributes["additional_certs.0.alias"] == "" {
							return fmt.Errorf("expected additional cert alias to be set")
						}

						if rs.Primary.Attributes["additional_certs.0.certificate"] == "" {
							return fmt.Errorf("expected additional cert certificate to be set")
						}

						return nil
					},
				),
			},
		},
	})
}

// Config that creates a JKS resource and reads it with the data source.
func testAccJKSDataSourceReadConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "source" {
  entries = [
    {
      private_key       = %[1]q
      certificate      = %[2]q
      certificate_chain = [%[3]q]
    }
  ]
  password = "testpassword"
}

data "crypto_jks" "test" {
  jks      = crypto_jks.source.jks
  password = "testpassword"
}
`, privateKey, certificate, chainCert)
}

func TestAccJKSDataSourceOnlyAdditionalCerts(t *testing.T) {
	_, _, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Create JKS with only additional certs (no private key entries)
			{
				Config: testAccJKSDataSourceOnlyAdditionalCertsConfig(testChainCert),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.crypto_jks.test",
						tfjsonpath.New("id"),
						knownvalue.NotNull(),
					),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.crypto_jks.test", "id"),
					// Verify we extracted only additional certs
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.crypto_jks.test"]
						if !ok {
							return fmt.Errorf("JKS data source not found")
						}

						// Check that no entries were extracted
						entriesCount := rs.Primary.Attributes["entries.#"]
						if entriesCount != "0" && entriesCount != "" {
							return fmt.Errorf("expected 0 entries, got %s", entriesCount)
						}

						// Check that additional_certs were extracted
						additionalCertsCount := rs.Primary.Attributes["additional_certs.#"]
						if additionalCertsCount != "2" {
							return fmt.Errorf("expected 2 additional certs, got %s", additionalCertsCount)
						}

						// Verify the first additional cert has required fields
						if rs.Primary.Attributes["additional_certs.0.alias"] == "" {
							return fmt.Errorf("expected additional cert 0 alias to be set")
						}

						if rs.Primary.Attributes["additional_certs.0.certificate"] == "" {
							return fmt.Errorf("expected additional cert 0 certificate to be set")
						}

						// Verify the second additional cert has required fields
						if rs.Primary.Attributes["additional_certs.1.alias"] == "" {
							return fmt.Errorf("expected additional cert 1 alias to be set")
						}

						if rs.Primary.Attributes["additional_certs.1.certificate"] == "" {
							return fmt.Errorf("expected additional cert 1 certificate to be set")
						}

						return nil
					},
				),
			},
		},
	})
}

func TestAccJKSDataSourceInvalidJKS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccJKSDataSourceInvalidJKSConfig(),
				ExpectError: regexp.MustCompile("(JKS Decode Error|Unable to decode base64 JKS|illegal base64 data)"),
			},
		},
	})
}

func TestAccJKSDataSourceWrongPassword(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccJKSDataSourceWrongPasswordConfig(testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("(JKS Load Error|Unable to load JKS)"),
			},
		},
	})
}

// Config that creates a JKS with additional certs and reads it.
func testAccJKSDataSourceReadConfigWithAdditionalCerts(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "source" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
    }
  ]
  additional_certs = [
    {
      certificate = %[3]q
    }
  ]
  password = "testpassword"
}

data "crypto_jks" "test" {
  jks      = crypto_jks.source.jks
  password = "testpassword"
}
`, privateKey, certificate, chainCert)
}

// Config that creates a JKS with only additional certs (no private key entries).
func testAccJKSDataSourceOnlyAdditionalCertsConfig(chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "source" {
  additional_certs = [
    {
      certificate = %[1]q
      alias       = "trusted-cert-1"
    },
    {
      certificate = %[1]q
      alias       = "trusted-cert-2"
    }
  ]
  password = "testpassword"
}

data "crypto_jks" "test" {
  jks      = crypto_jks.source.jks
  password = "testpassword"
}
`, chainCert)
}

// Config with invalid base64 JKS.
func testAccJKSDataSourceInvalidJKSConfig() string {
	return `
data "crypto_jks" "test" {
  jks      = "!!!not-valid-base64!!!"
  password = "testpassword"
}
`
}

// Config with wrong password.
func testAccJKSDataSourceWrongPasswordConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "source" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
    }
  ]
  password = "testpassword"
}

data "crypto_jks" "test" {
  jks      = crypto_jks.source.jks
  password = "wrongpassword"
}
`, privateKey, certificate, chainCert)
}
