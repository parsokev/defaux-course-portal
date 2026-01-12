api_addr                = "https://127.0.0.1:${VAULT_PORT}"
cluster_addr            = "https://127.0.0.1:${VAULT_CLUSTER_PORT}"
cluster_name            = "course-portal-app-vault-cluster"
disable_mlock           = true
ui                      = true

listener "tcp" {
    address             = "127.0.0.1:${VAULT_PORT}"
    tls_cert_file       = "./vault/local/certs/${VAULT_CERT_FILENAME}"
    tls_key_file        = "./vault/local/certs/${VAULT_CERT_KEY_FILENAME}"
}

backend "raft" {
    path                = "./vault/local/data"
    node_id             = "course-portal-app-vault-raft-node1"
}