#!/usr/bin/env bash

# Vault global configuration settings
VAULT_ADDR=your-full-vault-address
VAULT_PROXY_ADDR=your-full-external-nginx-server-address
VAULT_SKIP_VERIFY=false
VAULT_CERT_PATH='path/to/your/vault-certificate-file'
VAULT_CERT_KEY_PATH='path/to/your/vault-certificate-private-key-file'
SECRET_MOUNT_PATH=path/to/root/directory/of/enabled/secret
SECRET_PATH=path/to/the/secret/file/within/enabled/secret

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

exp_envs="VAULT_ADDR=$VAULT_ADDR VAULT_PROXY_ADDR=$VAULT_PROXY_ADDR VAULT_SKIP_VERIFY=$VAULT_SKIP_VERIFY "
exp_envs+="SECRET_MOUNT_PATH=$SECRET_MOUNT_PATH SECRET_PATH=$SECRET_PATH "
exp_envs+="VAULT_CERT_PATH=$VAULT_CERT_PATH VAULT_CERT_KEY_PATH=$VAULT_CERT_KEY_PATH python ./utils/unseal_vault.py"

sops --config ./sops/.sops.yaml exec-env ./secrets/.extended-vault-keys.enc.env "$exp_envs"