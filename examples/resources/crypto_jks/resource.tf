resource "crypto_jks" "example" {
  password = "changeit"

  entries = [
    {
      private_key       = file("${path.module}/server-key.pem")
      certificate       = file("${path.module}/server-cert.pem")
      certificate_chain = []
      alias             = "server"
    }
  ]

  additional_certs = [
    {
      certificate = file("${path.module}/ca-cert.pem")
      alias       = "ca"
    }
  ]
}

output "jks_content" {
  value     = crypto_jks.example.jks
  sensitive = true
}

# Example with base JKS
resource "crypto_jks" "with_base" {
  base_jks = filebase64("${path.module}/base-keystore.jks")
  password = "changeit"

  entries = [
    {
      private_key       = file("${path.module}/new-key.pem")
      certificate       = file("${path.module}/new-cert.pem")
      certificate_chain = []
      alias             = "new-entry"
    }
  ]
}
