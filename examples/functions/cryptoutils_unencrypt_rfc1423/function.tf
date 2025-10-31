output "example" {
  value = provider::crypto::unencrypt_rfc1423(file("${path.module}/cert.key"), "test")
}