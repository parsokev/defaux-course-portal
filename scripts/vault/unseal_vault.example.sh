#!/usr/bin/env bash

VAULT_ADDR=your-full-vault-address
VAULT_PROXY_ADDR=your-full-external-nginx-server-address
VAULT_SKIP_VERIFY=false
VAULT_CERT_PATH='path/to/your/vault-certificate-file'
VAULT_CERT_KEY_PATH='path/to/your/vault-certificate-private-key-file'
SECRET_MOUNT_PATH=path/to/root/directory/of/enabled/secret
SECRET_PATH=path/to/the/secret/file/within/enabled/secret

exp_envs="VAULT_ADDR=$VAULT_ADDR VAULT_PROXY_ADDR=$VAULT_PROXY_ADDR VAULT_SKIP_VERIFY=$VAULT_SKIP_VERIFY "
exp_envs+="SECRET_MOUNT_PATH=$SECRET_MOUNT_PATH SECRET_PATH=$SECRET_PATH "
exp_envs+="VAULT_CERT_PATH=$VAULT_CERT_PATH VAULT_CERT_KEY_PATH=$VAULT_CERT_KEY_PATH python ./utils/unseal_vault.py"

sops --config ./sops/.sops.yaml exec-env ./secrets/.extended-vault-keys.enc.env "$exp_envs"