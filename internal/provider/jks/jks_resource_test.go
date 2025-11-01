// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider"
	"github.com/mpieters3/terraform-provider-crypto/internal/provider/jks"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestAccJKSResource(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() { provider.TestAccPreCheck(t) },

		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: provider.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccJKSResourceConfig(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_jks.test", "jks"),
					// Verify we can decode and load the JKS
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["crypto_jks.test"]
						if !ok {
							return fmt.Errorf("JKS resource not found")
						}

						jksBase64 := rs.Primary.Attributes["jks"]
						jksBytes, err := base64.StdEncoding.DecodeString(jksBase64)
						if err != nil {
							return fmt.Errorf("failed to decode base64 JKS: %v", err)
						}

						// Try to load the keystore
						ks := keystore.New()
						if err := ks.Load(bytes.NewReader(jksBytes), []byte("testpassword")); err != nil {
							return fmt.Errorf("failed to load JKS: %v", err)
						}

						return nil
					},
				),
			},
			// Update testing - change the alias
			{
				Config: testAccJKSResourceConfigUpdated(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_jks.test", "jks"),
					resource.TestCheckResourceAttr("crypto_jks.test", "entries.0.alias", "updated-cert"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccJKSResourceConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "test" {
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

func testAccJKSResourceConfigUpdated(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "test" {
  entries = [
    {
      private_key       = %[1]q
      certificate      = %[2]q
      certificate_chain = [%[3]q]
      alias            = "updated-cert"
    }
  ]
  password = "testpassword"
}
`, privateKey, certificate, chainCert)
}

func createTestJKS(password string) (string, error) {
	ks := keystore.New()

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return "", fmt.Errorf("failed to create test JKS: %v", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func TestAccJKSResourceWithBaseJKS(t *testing.T) {
	testPrivateKey, testCertificate, testChainCert := jks.GenerateJKSTestCertAndKey(t)

	baseJKS, err := createTestJKS("testpassword")
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
			// Create with base JKS
			{
				Config: testAccJKSResourceConfigWithBaseJKS(baseJKS, testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("crypto_jks.test", "jks"),
					resource.TestCheckResourceAttr("crypto_jks.test", "base_jks", baseJKS),
					testVerifyJKSContent("crypto_jks.test"),
				),
			},
			// Invalid base JKS
			{
				Config:      testAccJKSResourceConfigWithBaseJKS("invalid-base64", testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("Unable to decode base64 JKS"),
			},
			// Wrong password for base JKS
			{
				Config:      testAccJKSResourceConfigWithWrongPassword(baseJKS, testPrivateKey, testCertificate, testChainCert),
				ExpectError: regexp.MustCompile("Unable to load base JKS"),
			},
		},
	})
}

func testAccJKSResourceConfigWithBaseJKS(baseJKS, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "test" {
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
`, baseJKS, privateKey, certificate, chainCert)
}

func testAccJKSResourceConfigWithWrongPassword(baseJKS, privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "crypto_jks" "test" {
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
`, baseJKS, privateKey, certificate, chainCert)
}

func testVerifyJKSContent(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("JKS resource not found: %s", resourceName)
		}

		jksBase64 := rs.Primary.Attributes["jks"]
		jksBytes, err := base64.StdEncoding.DecodeString(jksBase64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 JKS: %v", err)
		}

		// Try to load the keystore
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(jksBytes), []byte("testpassword")); err != nil {
			return fmt.Errorf("failed to load JKS: %v", err)
		}

		// Check if the alias exists in the keystore
		aliases := ks.Aliases()

		if !sliceContains(aliases, "test-cert") {
			return fmt.Errorf("expected alias 'test-cert' not found in keystore")
		}

		return nil
	}
}

func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
