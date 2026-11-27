# ============================================================
# GitOps Secret Shield – Vault Production Config
# ============================================================
storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = true          # Enable TLS in production with cert_file/key_file
  # tls_cert_file = "/vault/ssl/vault.crt"
  # tls_key_file  = "/vault/ssl/vault.key"
}

api_addr     = "http://0.0.0.0:8200"
cluster_addr = "http://0.0.0.0:8201"
ui           = false
