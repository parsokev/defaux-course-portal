#!/usr/bin/env bash

# Vault global configuration settings
VAULT_ADDR=https://<your-vault-service-host-address-and-port>
VAULT_PROXY_ADDR=http://<your-nginx-server-external-host-address-and-port>
VAULT_SKIP_VERIFY=set-to-false-for-local-hosting-else-true
VAULT_CERT_PATH=./vault/local/certs/<your-full-cert-file-name>
VAULT_CERT_KEY_PATH=./vault/local/certs/<your-full-cert-private-key-name>

# Imported PGP Encyrption Key configuration settings
GPG_HOME=relative/path/to/gnupg/home/directory/or/os/shortcut

# PGP Encryption key set #1
UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/your-rawbase64-pgp-public-key-file-for-encrypting-first-unseal-key)
UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/your-rawbase64-pgp-public-key-file-for-encrypting-second-unseal-key)
UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/your-rawbase64-pgp-public-key-file-for-encrypting-third-unseal-key)
TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/your-rawbase64-pgp-public-key-file-for-encrypting-vault-user-token)

# PGP Encryption key set #2
ALT_UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/your-rawbase64-alt-pgp-public-key-file-for-encrypting-first-unseal-key)
ALT_UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/your-rawbase64-alt-pgp-public-key-file-for-encrypting-second-unseal-key)
ALT_UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/your-rawbase64-alt-pgp-public-key-file-for-encrypting-third-unseal-key)
ALT_TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/your-rawbase64-alt-pgp-public-key-file-for-encrypting-vault-user-token)

# Global file configurations
ORIGINAL_ENV_FILE=./secrets/your-encrypted-vault-credentials-filename
SOPS_CONFIG_FILE=./sops/your-sops-config-filename
CRED_FILE=relative/path/to/the/authorized/service/account/credentials/file

# Vault KV secrets configuation settings
SECRET_MOUNT_PATH=your-enabled-kv-secret-path-name
SECRET_PATH=path-to-kv-secret-to-accessed-for-key-value-pair-secrets

# Vault Transit secret configuration settings (leave with default values if not being used)
TRANSIT_MOUNT_PATH=your-enabled-transit-secret-path
TRANSIT_KEY=path-to-transit-encryption-key-to-be-applied

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