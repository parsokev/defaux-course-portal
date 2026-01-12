#!/usr/bin/env bash

# Vault global configuration settings
VAULT_ADDR=https://0.0.0.0:8200
VAULT_PROXY_ADDR=http://127.0.0.1:8800
VAULT_SKIP_VERIFY=false
VAULT_CERT_PATH='./vault/local/certs/vault-cert.pem'
VAULT_CERT_KEY_PATH='./vault/local/certs/vault-key.pem'

# Imported PGP Encyrption Key configuration settings
GPG_HOME=~/.gnupg

# PGP Encryption key set #1
UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/pbkpSK1.b64.asc)
UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/pbkpSK2.b64.asc)
UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/pbkpSK3.b64.asc)
TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/pbkpRK1.b64.asc)

# PGP Encryption key set #2
ALT_UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/pbkpAltSK1.b64.asc)
ALT_UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/pbkpAltSK2.b64.asc)
ALT_UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/pbkpAltSK3.b64.asc)
ALT_TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/pbkpAltRK1.b64.asc)

# Vault KV secrets configuation settings
SECRET_MOUNT_PATH=app-secrets
SECRET_PATH=creds

# Vault Transit secret configuration settings
TRANSIT_MOUNT_PATH=sops
TRANSIT_KEY=crypt-key2

# Global file configurations
ORIGINAL_ENV_FILE=./secrets/.extended-vault-keys.enc.env
SOPS_CONFIG_FILE=./sops/.sops.yaml
CRED_FILE=./secrets/SA-creds.json

set +o history

exp_envs="VAULT_ADDR=$VAULT_ADDR VAULT_PROXY_ADDR=$VAULT_PROXY_ADDR VAULT_SKIP_VERIFY=$VAULT_SKIP_VERIFY VAULT_CERT_PATH=$VAULT_CERT_PATH VAULT_CERT_KEY_PATH=$VAULT_CERT_KEY_PATH "
exp_envs+="GPG_HOME=$GPG_HOME UNSEAL_CRYPT_KEY1=$UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2=$UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3=$UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY=$TOKEN_CRYPT_KEY "
exp_envs+="ALT_UNSEAL_CRYPT_KEY1=$ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2=$ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3=$ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY=$ALT_TOKEN_CRYPT_KEY "
exp_envs+="SECRET_MOUNT_PATH=$SECRET_MOUNT_PATH SECRET_PATH=$SECRET_PATH TRANSIT_MOUNT_PATH=$TRANSIT_MOUNT_PATH TRANSIT_KEY=$TRANSIT_KEY "
exp_envs+="ORIGINAL_ENV_FILE=$ORIGINAL_ENV_FILE SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE CRED_FILE=$CRED_FILE "
exp_envs+="python -m utils.update_gcp_secrets"

sops --config $SOPS_CONFIG_FILE exec-env $ORIGINAL_ENV_FILE "$exp_envs"

history -c

unset VAULT_ADDR VAULT_PROXY_ADDR VAULT_SKIP_VERIFY SECRET_MOUNT_PATH SECRET_PATH TRANSIT_MOUNT_PATH TRANSIT_KEY VAULT_CERT_PATH VAULT_CERT_KEY_PATH
unset UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY
unset ORIGINAL_ENV_FILE SOPS_CONFIG_FILE CRED_FILE