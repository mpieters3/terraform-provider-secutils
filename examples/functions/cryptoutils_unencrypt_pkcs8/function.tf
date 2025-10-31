output "example" {
  value = provider::cryptoutils::unencrypt_pkcs8(file("${path.module}/cert.key"), "test")
}