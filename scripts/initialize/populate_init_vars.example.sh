#!/usr/bin/env bash

# Vault Configurations
export VAULT_PORT=8200
export VAULT_CLUSTER_PORT=8201
export VAULT_HOSTNAME="127.0.0.1"
export VAULT_ADDR="https://${VAULT_HOSTNAME}:${VAULT_PORT}"
export VAULT_CLUSTER_ADDR="https://${VAULT_HOSTNAME}:${VAULT_CLUSTER_PORT}"
export VAULT_SKIP_VERIFY=true

export VAULT_CERT_FILENAME=your-vault-ssl-certificate-filename.pem
export VAULT_CERT_KEY_FILENAME=your-vault-ssl-certificate-key-filename.pem

# Filenames/paths settings
export VAULT_TEXT_FILE=./secrets/your-plaintext-encoded-vault-vars-txt-file
export VAULT_JSON_FILE=./secrets/your-plaintext-encoded-vault-vars-json-file
export VAULT_ENV_FILE=./secrets/your-encrypted-vault-creds-env-file
export TMP_FILE=your-temp-file-name

# PGP-encryption file settings
export PGP_KEY_1_FILE=./path/to/your-local-pgp-key1-binary-or-b64encoded-file
export PGP_KEY_2_FILE=./path/to/your-local-pgp-key2-binary-or-b64encoded-file
export PGP_KEY_3_FILE=./path/to/your-local-pgp-key3-binary-or-b64encoded-file
export PGP_KEY_4_FILE=./path/to/your-local-pgp-key4-binary-or-b64encoded-file
export ENV_ENC_FINGERPRINT=fingerprint-of-chosen-pgp-key-for-text-file-encryption
export SOPS_CONFIG_FILE=./path/to/your/sops/config/file


env_sub_vars='${VAULT_PORT} ${VAULT_CLUSTER_PORT} ${VAULT_HOSTNAME} ${VAULT_ADDR} ${VAULT_CLUSTER_ADDR} ${VAULT_SKIP_VERIFY} '
env_sub_vars+='${VAULT_CERT_FILENAME} ${VAULT_CERT_KEY_FILENAME} '
env_sub_vars+='${VAULT_TEXT_FILE} ${VAULT_JSON_FILE} ${VAULT_ENV_FILE} ${TMP_FILE} '
env_sub_vars+='${PGP_KEY_1_FILE} ${PGP_KEY_2_FILE} ${PGP_KEY_3_FILE} ${PGP_KEY_4_FILE} ${ENV_ENC_FINGERPRINT} ${SOPS_CONFIG_FILE}'

envsubst "$env_sub_vars" < ./scripts/initialize/initialize_vault.template.sh > ./scripts/initialize/initialize_vault.sh
envsubst "$env_sub_vars" < ./vault/local/config/config.start.template.hcl > ./vault/local/config/config.start.hcl
envsubst "$env_sub_vars" < ./vault/local/config/config.init.template.hcl > ./vault/local/config/config.init.hcl
envsubst "$env_sub_vars" < ./vault/config/config.template.hcl > ./vault/config/config.hcl
envsubst "$env_sub_vars" < ./scripts/initialize/vault_startup.template.sh > ./scripts/initialize/vault_startup.sh

unset VAULT_PORT VAULT_CLUSTER_PORT VAULT_HOSTNAME VAULT_ADDR VAULT_CLUSTER_ADDR VAULT_SKIP_VERIFY
unset VAULT_CERT_FILENAME VAULT_CERT_KEY_FILENAME
unset VAULT_TEXT_FILE VAULT_JSON_FILE VAULT_ENV_FILE TMP_FILE PGP_KEY_1_FILE PGP_KEY_2_FILE PGP_KEY_3_FILE PGP_KEY_4_FILE 
unset ENV_ENC_FINGERPRINT SOPS_CONFIG_FILE