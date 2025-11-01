data "crypto_jks" "example" {
  jks      = filebase64("${path.module}/keystore.jks")
  password = "changeit"
}

output "private_keys" {
  value     = data.crypto_jks.example.entries
  sensitive = true
}

output "trusted_certs" {
  value = data.crypto_jks.example.additional_certs
}
