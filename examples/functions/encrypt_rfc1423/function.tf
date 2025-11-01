output "example" {
  value     = provider::crypto::encrypt_rfc1423(file("${path.module}/cert.key"), "mypassword")
  sensitive = true
}
