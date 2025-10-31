output "example" {
  value = provider::cryptoutils::unencrypt_rfc1423(file("${path.module}/cert.key"), "test")
}