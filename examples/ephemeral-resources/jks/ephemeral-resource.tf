ephemeral "crypto_jks" "example" {
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
  value     = ephemeral.crypto_jks.example.jks
  sensitive = true
}
