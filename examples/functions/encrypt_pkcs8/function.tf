output "example" {
  value     = provider::crypto::encrypt_pkcs8(file("${path.module}/cert.key"), "mypassword")
  sensitive = true
}
