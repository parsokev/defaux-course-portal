api_addr                = "https://vault-store:${VAULT_PORT}"
cluster_addr            = "https://vault-store:${VAULT_CLUSTER_PORT}"
cluster_name            = "course-portal-app-vault-cluster"
disable_mlock           = true
ui                      = true

listener "tcp" {
    address             = "vault-store:${VAULT_PORT}"
    tls_cert_file       = "/certs/${VAULT_CERT_FILENAME}"
    tls_key_file        = "/certs/${VAULT_CERT_KEY_FILENAME}"
}

backend "raft" {
    path                = "/vault/data"
    node_id             = "course-portal-app-vault-server"
}