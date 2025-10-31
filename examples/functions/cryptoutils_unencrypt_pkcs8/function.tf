output "example" {
  value = provider::crypto::unencrypt_pkcs8(file("${path.module}/cert.key"), "test")
}