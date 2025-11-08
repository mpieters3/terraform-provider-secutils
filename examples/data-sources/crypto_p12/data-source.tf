# Generate certificates for the example
resource "tls_private_key" "server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name  = "server.example.com"
    organization = "Example Org"
  }

  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Create a P12 to read
resource "crypto_p12" "source" {
  password = "changeit"

  entries = [
    {
      private_key       = tls_private_key.server.private_key_pem
      certificate       = tls_self_signed_cert.server.cert_pem
      certificate_chain = []
      alias             = "server"
    }
  ]
}

# Read the P12 file using data source
data "crypto_p12" "example" {
  p12      = crypto_p12.source.p12
  password = "changeit"
}

# Access the private key entry (if present)
output "private_key" {
  value     = data.crypto_p12.example.entry.private_key
  sensitive = true
}

output "certificate" {
  value = data.crypto_p12.example.entry.certificate
}

output "certificate_chain" {
  value = data.crypto_p12.example.entry.certificate_chain
}

# Access additional certificates
output "trusted_certs" {
  value = data.crypto_p12.example.additional_certs
}

# Read a passwordless P12 file
resource "crypto_p12" "passwordless_source" {
  password = ""

  entries = [
    {
      private_key       = tls_private_key.server.private_key_pem
      certificate       = tls_self_signed_cert.server.cert_pem
      certificate_chain = []
      alias             = "server"
    }
  ]
}

data "crypto_p12" "passwordless" {
  p12      = crypto_p12.passwordless_source.p12
  password = ""
}

# Use with another resource to create a new P12
resource "crypto_p12" "new_from_existing" {
  password = "newpassword"

  entries = [
    {
      private_key       = data.crypto_p12.example.entry.private_key
      certificate       = data.crypto_p12.example.entry.certificate
      certificate_chain = data.crypto_p12.example.entry.certificate_chain
      alias             = "migrated"
    }
  ]
}

# Example: Read P12 from file (if you have an existing P12 file)
# data "crypto_p12" "from_file" {
#   p12      = filebase64("${path.module}/existing-keystore.p12")
#   password = "changeit"
# }
