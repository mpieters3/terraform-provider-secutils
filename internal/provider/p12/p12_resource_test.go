// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12_test

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/p12"
	"software.sslmate.com/src/go-pkcs12"
)

func TestAccP12Resource(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() { provider.TestAccPreCheck(t) },

		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccP12ResourceConfig(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_p12.test", "p12"),
					// Verify we can decode and load the P12
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["crypto_p12.test"]
						if !ok {
							return fmt.Errorf("P12 resource not found")
						}

						p12Base64 := rs.Primary.Attributes["p12"]
						p12Bytes, err := base64.StdEncoding.DecodeString(p12Base64)
						if err != nil {
							return fmt.Errorf("failed to decode base64 P12: %v", err)
						}

						// Try to decode the P12
						_, cert, caCerts, err := pkcs12.DecodeChain(p12Bytes, "testpassword")
						if err != nil {
							return fmt.Errorf("failed to decode P12: %v", err)
						}

						if cert == nil {
							return fmt.Errorf("expected certificate to be present")
						}

						if len(caCerts) != 1 {
							return fmt.Errorf("expected 1 CA cert, got %d", len(caCerts))
						}

						return nil
					},
				),
			},
			// Update testing - change the alias (should trigger recreation)
			{
				Config: testAccP12ResourceConfigUpdated(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_p12.test", "p12"),
					resource.TestCheckResourceAttr("crypto_p12.test", "entries.0.alias", "updated-cert"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccP12ResourceConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "test-cert"
    }
  ]
  password = "testpassword"
}`, privateKey, certificate, chainCert)
}

func testAccP12ResourceConfigUpdated(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "updated-cert"
    }
  ]
  password = "testpassword"
}
`, privateKey, certificate, chainCert)
}

func createTestP12(password string) (string, error) {
	// Create an empty P12 with just a trust store
	p12Bytes, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{}, password)
	if err != nil {
		return "", fmt.Errorf("failed to create test P12: %v", err)
	}

	return base64.StdEncoding.EncodeToString(p12Bytes), nil
}

func TestAccP12ResourceWithBaseP12(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	_, err := createTestP12("testpassword")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Note: base_p12 is not currently implemented in P12, but this test
			// documents the expected behavior if/when it is added
			// For now, we test without base_p12
			{
				Config: testAccP12ResourceConfig(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_p12.test", "p12"),
					testVerifyP12Content("crypto_p12.test"),
				),
			},
			// Invalid base P12
			{
				Config:      testAccP12ResourceConfigWithInvalidBase("invalid-base64", testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("(Unable to decode|illegal base64 data)"),
			},
		},
	})
}

func testAccP12ResourceConfigWithInvalidBase(baseP12, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
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
`, baseP12, privateKey, certificate, chainCert)
}

func testVerifyP12Content(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("P12 resource not found: %s", resourceName)
		}

		p12Base64 := rs.Primary.Attributes["p12"]
		p12Bytes, err := base64.StdEncoding.DecodeString(p12Base64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 P12: %v", err)
		}

		// Try to decode the P12
		privateKey, cert, caCerts, err := pkcs12.DecodeChain(p12Bytes, "testpassword")
		if err != nil {
			return fmt.Errorf("failed to decode P12: %v", err)
		}

		if privateKey == nil {
			return fmt.Errorf("expected private key to be present")
		}

		if cert == nil {
			return fmt.Errorf("expected certificate to be present")
		}

		if len(caCerts) == 0 {
			return fmt.Errorf("expected at least one CA cert")
		}

		return nil
	}
}

func TestAccP12ResourceOnlyAdditionalCerts(t *testing.T) {
	_, _, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Create P12 with only additional certs (no private key)
			{
				Config: testAccP12ResourceConfigOnlyAdditionalCerts(testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_p12.test", "p12"),
					// Verify the P12 contains only certificates
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["crypto_p12.test"]
						if !ok {
							return fmt.Errorf("P12 resource not found")
						}

						p12Base64 := rs.Primary.Attributes["p12"]
						p12Bytes, err := base64.StdEncoding.DecodeString(p12Base64)
						if err != nil {
							return fmt.Errorf("failed to decode base64 P12: %v", err)
						}

						// Decode trust store
						certs, err := pkcs12.DecodeTrustStore(p12Bytes, "testpassword")
						if err != nil {
							return fmt.Errorf("failed to decode P12 trust store: %v", err)
						}

						if len(certs) != 2 {
							return fmt.Errorf("expected 2 certificates, got %d", len(certs))
						}

						return nil
					},
				),
			},
		},
	})
}

func testAccP12ResourceConfigOnlyAdditionalCerts(chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
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
`, chainCert)
}

func TestAccP12ResourceMultiplePrivateKeys(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Try to create P12 with multiple private keys - should fail with clear error
			{
				Config:      testAccP12ResourceConfigMultipleKeys(testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("P12 Library Limitation.*only supports encoding one private key"),
			},
		},
	})
}

func testAccP12ResourceConfigMultipleKeys(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
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
`, privateKey, certificate, chainCert)
}

func TestAccP12ResourcePasswordless(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := p12.GenerateP12TestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { provider.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Create passwordless P12
			{
				Config: testAccP12ResourceConfigPasswordless(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_p12.test", "p12"),
					// Verify we can decode the passwordless P12
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["crypto_p12.test"]
						if !ok {
							return fmt.Errorf("P12 resource not found")
						}

						p12Base64 := rs.Primary.Attributes["p12"]
						p12Bytes, err := base64.StdEncoding.DecodeString(p12Base64)
						if err != nil {
							return fmt.Errorf("failed to decode base64 P12: %v", err)
						}

						// Try to decode the P12 with empty password
						_, cert, caCerts, err := pkcs12.DecodeChain(p12Bytes, "")
						if err != nil {
							return fmt.Errorf("failed to decode passwordless P12: %v", err)
						}

						if cert == nil {
							return fmt.Errorf("expected certificate to be present")
						}

						if len(caCerts) != 1 {
							return fmt.Errorf("expected 1 CA cert, got %d", len(caCerts))
						}

						return nil
					},
				),
			},
		},
	})
}

func testAccP12ResourceConfigPasswordless(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_p12" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate       = %[2]q
      certificate_chain = [%[3]q]
      alias             = "test-cert"
    }
  ]
  password = ""
}`, privateKey, certificate, chainCert)
}
