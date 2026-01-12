#!/usr/bin/env bash

# Vault global configuration settings
VAULT_ADDR=${VAULT_ADDR}
VAULT_PROXY_ADDR=${VAULT_PROXY_ADDR}
VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY}
VAULT_CERT_PATH=${VAULT_CERT_PATH}
VAULT_CERT_KEY_PATH=${VAULT_CERT_KEY_PATH}

# Imported PGP Encyrption Key configuration settings
PGP_FINGERPRINT_1=${PGP_FINGERPRINT_1}
GPG_HOME=${GPG_HOME}

# PGP Encryption key set #1
UNSEAL_CRYPT_KEY1=${UNSEAL_CRYPT_KEY1}
UNSEAL_CRYPT_KEY2=${UNSEAL_CRYPT_KEY2}
UNSEAL_CRYPT_KEY3=${UNSEAL_CRYPT_KEY3}
TOKEN_CRYPT_KEY=${TOKEN_CRYPT_KEY}

# PGP Encryption key set #2
ALT_UNSEAL_CRYPT_KEY1=${ALT_UNSEAL_CRYPT_KEY1}
ALT_UNSEAL_CRYPT_KEY2=${ALT_UNSEAL_CRYPT_KEY2}
ALT_UNSEAL_CRYPT_KEY3=${ALT_UNSEAL_CRYPT_KEY3}
ALT_TOKEN_CRYPT_KEY=${ALT_TOKEN_CRYPT_KEY}

# Vault KV secrets configuation settings
SECRET_MOUNT_PATH=${SECRET_MOUNT_PATH}
SECRET_PATH=${SECRET_PATH}

# Vault Transit secret configuration settings
TRANSIT_MOUNT_PATH=${TRANSIT_MOUNT_PATH}
TRANSIT_KEY=${TRANSIT_KEY}

# Flask server configuration settings
HOSTNAME=${HOSTNAME}
PORT=${PORT}
APP_ENV='prod'


# External Nginx reverse-proxy server configuration settings
PROXY_ADDR=${PROXY_ADDR}

SOPS_CONFIG_FILE=${SOPS_CONFIG_FILE}
ORIGINAL_ENV_FILE=${ORIGINAL_ENV_FILE}

exp_envs="VAULT_ADDR=$VAULT_ADDR VAULT_PROXY_ADDR=$VAULT_PROXY_ADDR VAULT_SKIP_VERIFY=$VAULT_SKIP_VERIFY "
exp_envs+="UNSEAL_CRYPT_KEY1=$UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2=$UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3=$UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY=$TOKEN_CRYPT_KEY "
exp_envs+="SECRET_MOUNT_PATH=$SECRET_MOUNT_PATH SECRET_PATH=$SECRET_PATH HOSTNAME=$HOSTNAME PORT=$PORT PGP_FINGERPRINT_1=$PGP_FINGERPRINT_1 "
exp_envs+="TRANSIT_MOUNT_PATH=$TRANSIT_MOUNT_PATH PROXY_ADDR=$PROXY_ADDR GPG_HOME=$GPG_HOME ALT_TOKEN_CRYPT_KEY=$ALT_TOKEN_CRYPT_KEY "
exp_envs+="ALT_UNSEAL_CRYPT_KEY1=$ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2=$ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3=$ALT_UNSEAL_CRYPT_KEY3 "
exp_envs+="TRANSIT_KEY=$TRANSIT_KEY VAULT_CERT_PATH=$VAULT_CERT_PATH VAULT_CERT_KEY_PATH=$VAULT_CERT_KEY_PATH APP_ENV=$APP_ENV "
exp_envs+="gunicorn --config gunicorn.conf.py wsgi:app"

# Ensure all public/private keypairs of pgp keys used to originally encrypt vault keys file and for runtime decryption/encryption is mounted to flask-app container at runtime

gpg --import ./pgp_config/img_keys/pgppkEVK1A.asc # PGP Key used to originally encrypt extended vault keys file
gpg --import ./pgp_config/img_keys/pgppkEVK1B.asc
 
gpg --import ./pgp_config/img_keys/pgppkSK1A.asc # PGP Key used to originally encrypt first unseal key
gpg --import ./pgp_config/img_keys/pgppkSK1B.asc

gpg --import ./pgp_config/img_keys/pgppkSK2A.asc # PGP Key used to originally encrypt second unseal key
gpg --import ./pgp_config/img_keys/pgppkSK2B.asc

gpg --import ./pgp_config/img_keys/pgppkSK3A.asc # PGP Key used to originally encrypt third unseal key
gpg --import ./pgp_config/img_keys/pgppkSK3B.asc

gpg --import ./pgp_config/img_keys/pgppkRK1A.asc # PGP Key used to originally encrypt initial root token
gpg --import ./pgp_config/img_keys/pgppkRK1B.asc

gpg --import ./pgp_config/img_keys/pgppkAltEVKA.asc # Alternate PGP Key to encrypt extended vault keys file
gpg --import ./pgp_config/img_keys/pgppkAltEVKB.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK1A.asc # Alternate PGP Key to encrypt first unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK1B.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK2A.asc # Alternate PGP Key to encrypt second unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK2B.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK3A.asc # Alternate PGP Key to encrypt thrid unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK3B.asc

gpg --import ./pgp_config/img_keys/pgppkAltRK1A.asc # Alternate PGP Key for encrypting temporary root token 
gpg --import ./pgp_config/img_keys/pgppkAltRK1B.asc


sops --config $SOPS_CONFIG_FILE exec-env $ORIGINAL_ENV_FILE "$exp_envs"