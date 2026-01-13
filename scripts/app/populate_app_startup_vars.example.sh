#!/usr/bin/env bash

# Supplementary Configuration Variables
VAULT_HOSTNAME='vault-store'
VAULT_PORT=8200
EXTERNAL_PORT=8800
EXTERNAL_HOSTNAME='127.0.0.1'
VAULT_CERT_FILENAME='your-vault-ssl-certificate-filename.pem'
VAULT_CERT_KEY_FILENAME='your-vault-ssl-certificate-key-filename.pem'

UNSEAL_CRYPT_KEY1_FILE=./pgp_config/img_keys/pbkpSK1.b64.asc
UNSEAL_CRYPT_KEY2_FILE=./pgp_config/img_keys/pbkpSK2.b64.asc
UNSEAL_CRYPT_KEY3_FILE=./pgp_config/img_keys/pbkpSK3.b64.asc
TOKEN_CRYPT_KEY_FILE=./pgp_config/img_keys/pbkpRK1.b64.asc

ALT_UNSEAL_CRYPT_KEY1_FILE=./pgp_config/img_keys/pbkpAltSK1.b64.asc
ALT_UNSEAL_CRYPT_KEY2_FILE=./pgp_config/img_keys/pbkpAltSK2.b64.asc
ALT_UNSEAL_CRYPT_KEY3_FILE=./pgp_config/img_keys/pbkpAltSK3.b64.asc
ALT_TOKEN_CRYPT_KEY_FILE=./pgp_config/img_keys/pbkpAltRK1.b64.asc

# Flask server configuration settings
export HOSTNAME=0.0.0.0
export PORT=8500

# Vault global configuration settings
export VAULT_ADDR=https://${VAULT_HOSTNAME}:${VAULT_PORT}
export VAULT_PROXY_ADDR=http://${EXTERNAL_HOSTNAME}:${EXTERNAL_PORT}/vault
export VAULT_SKIP_VERIFY=false
export VAULT_CERT_PATH=./vault/certs/${VAULT_CERT_FILENAME}
export VAULT_CERT_KEY_PATH=./vault/certs/${VAULT_CERT_KEY_FILENAME}

# External Nginx reverse-proxy server configuration settings
export PROXY_ADDR=http://${EXTERNAL_HOSTNAME}:${EXTERNAL_PORT}

# PGP Encryption key set #1
export UNSEAL_CRYPT_KEY1=$(cat ${UNSEAL_CRYPT_KEY1_FILE})
export UNSEAL_CRYPT_KEY2=$(cat ${UNSEAL_CRYPT_KEY2_FILE})
export UNSEAL_CRYPT_KEY3=$(cat ${UNSEAL_CRYPT_KEY3_FILE})
export TOKEN_CRYPT_KEY=$(cat ${TOKEN_CRYPT_KEY_FILE})

# PGP Encryption key set #2
export ALT_UNSEAL_CRYPT_KEY1=$(cat ${UNSEAL_CRYPT_KEY1_FILE})
export ALT_UNSEAL_CRYPT_KEY2=$(cat ${UNSEAL_CRYPT_KEY2_FILE})
export ALT_UNSEAL_CRYPT_KEY3=$(cat ${UNSEAL_CRYPT_KEY3_FILE})
export ALT_TOKEN_CRYPT_KEY=$(cat ${ALT_TOKEN_CRYPT_KEY_FILE})

# Vault KV secrets configuation settings
export SECRET_MOUNT_PATH=your-enabled-kv-secret-path-name
export SECRET_PATH=path-to-kv-secret-to-accessed-for-key-value-pair-secrets

# Vault Transit secret configuration settings (leave with default values if not being used)
export TRANSIT_MOUNT_PATH=your-enabled-transit-secret-path
export TRANSIT_KEY=path-to-transit-encryption-key-to-be-applied

# Encryption configuration settings
export PGP_FINGERPRINT_1=fingerprint-of-pgp-key-used-to-encrypt-vault-creds-file
export GPG_HOME=/root/.gnupg
export SOPS_CONFIG_FILE=./path/to/your/sops/config/file
export ORIGINAL_ENV_FILE=./secrets/your-encrypted-vault-creds-env-file


env_sub_vars='${VAULT_ADDR} ${VAULT_PROXY_ADDR} ${VAULT_SKIP_VERIFY} '
env_sub_vars+='${UNSEAL_CRYPT_KEY1} ${UNSEAL_CRYPT_KEY2} ${UNSEAL_CRYPT_KEY3} ${TOKEN_CRYPT_KEY} '
env_sub_vars+='${SECRET_MOUNT_PATH} ${SECRET_PATH} ${HOSTNAME} ${PORT} ${PGP_FINGERPRINT_1} '
env_sub_vars+='${TRANSIT_MOUNT_PATH} ${PROXY_ADDR} ${GPG_HOME} ${ALT_TOKEN_CRYPT_KEY} '
env_sub_vars+='${ALT_UNSEAL_CRYPT_KEY1} ${ALT_UNSEAL_CRYPT_KEY2} ${ALT_UNSEAL_CRYPT_KEY3} '
env_sub_vars+='${TRANSIT_KEY} ${VAULT_CERT_PATH} ${VAULT_CERT_KEY_PATH} '
env_sub_vars+='${UNSEAL_CRYPT_KEY1_FILE} ${UNSEAL_CRYPT_KEY2_FILE} ${UNSEAL_CRYPT_KEY3_FILE} '
env_sub_vars+='${TOKEN_CRYPT_KEY_FILE} ${ALT_UNSEAL_CRYPT_KEY1} ${ALT_UNSEAL_CRYPT_KEY2} '
env_sub_vars+='${ALT_UNSEAL_CRYPT_KEY3} ${ALT_TOKEN_CRYPT_KEY_FILE} ${SOPS_CONFIG_FILE} ${ORIGINAL_ENV_FILE}'

envsubst "$env_sub_vars" < ./scripts/app/start_app.deploy.template.sh > ./scripts/app/start_app.deploy.sh
envsubst "$env_sub_vars" < ./scripts/app/start_app.dev.template.sh > ./scripts/app/start_app.local.dev.sh
envsubst "$env_sub_vars" < ./scripts/app/start_app.prod.template.sh > ./scripts/app/start_app.local.prod.sh
envsubst "$env_sub_vars" < ./scripts/app/start_app.test.template.sh > ./scripts/app/start_app.test.sh

unset VAULT_HOSTNAME VAULT_PORT EXTERNAL_PORT EXTERNAL_HOSTNAME VAULT_CERT_FILENAME VAULT_CERT_KEY_FILENAME
unset HOSTNAME PORT VAULT_ADDR VAULT_PROXY_ADDR VAULT_SKIP_VERIFY VAULT_CERT_PATH VAULT_CERT_KEY_PATH
unset PROXY_ADDR UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY
unset ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY
unset SECRET_MOUNT_PATH SECRET_PATH TRANSIT_MOUNT_PATH TRANSIT_KEY
unset PGP_FINGERPRINT_1 GPG_HOME SOPS_CONFIG_FILE ORIGINAL_ENV_FILE
unset UNSEAL_CRYPT_KEY1_FILE UNSEAL_CRYPT_KEY2_FILE UNSEAL_CRYPT_KEY3_FILE TOKEN_CRYPT_KEY_FILE
unset ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY_FILE