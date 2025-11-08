# Generate a CA certificate
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "Example CA"
    organization = "Example Org"
  }

  validity_period_hours = 87600 # 10 years
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "key_encipherment",
    "digital_signature",
  ]
}

# Generate a server certificate
resource "tls_private_key" "server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name  = "server.example.com"
    organization = "Example Org"
  }
}

resource "tls_locally_signed_cert" "server" {
  cert_request_pem   = tls_cert_request.server.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 8760 # 1 year

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Basic P12 resource with password protection
resource "crypto_p12" "example" {
  password = "changeit"

  entries = [
    {
      private_key       = tls_private_key.server.private_key_pem
      certificate       = tls_locally_signed_cert.server.cert_pem
      certificate_chain = [tls_self_signed_cert.ca.cert_pem]
      alias             = "server"
    }
  ]
}

output "p12_content" {
  value     = crypto_p12.example.p12
  sensitive = true
}

# P12 with additional trusted certificates
resource "crypto_p12" "with_trust_store" {
  password = "changeit"

  entries = [
    {
      private_key       = tls_private_key.server.private_key_pem
      certificate       = tls_locally_signed_cert.server.cert_pem
      certificate_chain = []
      alias             = "server"
    }
  ]

  additional_certs = [
    {
      certificate = tls_self_signed_cert.ca.cert_pem
      alias       = "ca"
    }
  ]
}

# Passwordless P12 (may have compatibility issues)
resource "crypto_p12" "passwordless" {
  password = ""

  entries = [
    {
      private_key       = tls_private_key.server.private_key_pem
      certificate       = tls_locally_signed_cert.server.cert_pem
      certificate_chain = []
      alias             = "server"
    }
  ]
}

# Trust store only (no private keys)
resource "crypto_p12" "trust_store_only" {
  password = "changeit"

  additional_certs = [
    {
      certificate = tls_self_signed_cert.ca.cert_pem
      alias       = "root-ca"
    }
  ]
}

# Save P12 to file
resource "local_file" "p12_file" {
  content_base64 = crypto_p12.example.p12
  filename       = "${path.module}/keystore.p12"
}
