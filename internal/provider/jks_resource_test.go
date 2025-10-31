// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestAccJKSResource(t *testing.T) {
	// Test certificate and private key
	testPrivateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz8JzPHk1Fn6oK
gNwZqoVvKp5F0OcuXvj7oFjNCtVr1j7K+XhHNHgI1wL2HUmUQxc4q1cEk4Nrstxt
zEJgQyVg4P5mcBXu7HiBn+oPVHIjh+YZCWjGckjYgWvP1OvMJzBvKoUBv8dnqlv0
d9BPM/fQ1nqL9B5BWP1EOlnWL4C5HjQH4iu0tKDQy6BRFqwwJ8y8SZwtPvT4Ev4O
...
-----END PRIVATE KEY-----`

	testCertificate := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBGZeqM0kPpyVTwT+iyvLh4DjhYgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMjgxNjAwMDBaFw0yMzEw
...
-----END CERTIFICATE-----`

	testChainCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBGZeqM0kPpyVTwT+iyvLh4DjhYgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMjgxNjAwMDBaFw0yMzEw
...
-----END CERTIFICATE-----`

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },

		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccJKSResourceConfig(testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("cryptoutils_jks.test", "jks"),
					// Verify we can decode and load the JKS
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["cryptoutils_jks.test"]
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
					resource.TestCheckResourceAttrSet("cryptoutils_jks.test", "jks"),
					resource.TestCheckResourceAttr("cryptoutils_jks.test", "alias", "updated-cert"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccJKSResourceConfig(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "cryptoutils_jks" "test" {
  entries = [
    {
		private_key       = %[1]q
		certificate      = %[2]q
		certificate_chain = [%[3]q]
		password         = "testpassword"
		alias            = "test-cert"
	}
  ]
`, privateKey, certificate, chainCert)
}

func testAccJKSResourceConfigUpdated(privateKey, certificate, chainCert string) string {
	return fmt.Sprintf(`
resource "cryptoutils_jks" "test" {
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
	// Test certificate and private key
	testPrivateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz8JzPHk1Fn6oK
gNwZqoVvKp5F0OcuXvj7oFjNCtVr1j7K+XhHNHgI1wL2HUmUQxc4q1cEk4Nrstxt
zEJgQyVg4P5mcBXu7HiBn+oPVHIjh+YZCWjGckjYgWvP1OvMJzBvKoUBv8dnqlv0
d9BPM/fQ1nqL9B5BWP1EOlnWL4C5HjQH4iu0tKDQy6BRFqwwJ8y8SZwtPvT4Ev4O
...
-----END PRIVATE KEY-----`

	testCertificate := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBGZeqM0kPpyVTwT+iyvLh4DjhYgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMjgxNjAwMDBaFw0yMzEw
...
-----END CERTIFICATE-----`

	testChainCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBGZeqM0kPpyVTwT+iyvLh4DjhYgwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMjgxNjAwMDBaFw0yMzEw
...
-----END CERTIFICATE-----`

	baseJKS, err := createTestJKS("testpassword")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_0_0),
		},
		Steps: []resource.TestStep{
			// Create with base JKS
			{
				Config: testAccJKSResourceConfigWithBaseJKS(baseJKS, testPrivateKey, testCertificate, testChainCert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("cryptoutils_jks.test", "jks"),
					resource.TestCheckResourceAttr("cryptoutils_jks.test", "base_jks", baseJKS),
					testVerifyJKSContent("cryptoutils_jks.test"),
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
resource "cryptoutils_jks" "test" {
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
resource "cryptoutils_jks" "test" {
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
