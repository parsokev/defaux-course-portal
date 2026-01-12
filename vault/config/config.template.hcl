api_addr                = "https://vault-store:8200"
cluster_addr            = "https://vault-store:8201"
cluster_name            = "course-portal-app-vault-cluster"
disable_mlock           = true
ui                      = true

listener "tcp" {
    address       = "vault-store:8200"
    tls_cert_file = "/certs/vault-cert.pem"
    tls_key_file  = "/certs/vault-key.pem"
}

backend "raft" {
    path    = "/vault/data"
    node_id = "course-portal-app-vault-server"
}