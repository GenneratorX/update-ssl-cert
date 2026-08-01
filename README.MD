⚠️ ARCHIVED REPOSITORY ⚠️

Decided to use OpenTofu with acme/cloudflare/tls providers to generate SSL certificates and populate DNS records appropriately since I'm already using it to manage my infrastructure.

# Script for automating the creation of SSL certificates

## Features
* Create SSL certificates using a custom CSR
* Create SSL certificates using CertBot with CloudFlare DNS verification
* Back-up of private keys and certificates
* Update TLSA DNS entries for DANE
