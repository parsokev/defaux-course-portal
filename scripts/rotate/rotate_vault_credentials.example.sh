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

# Vault KV secrets configuation settings
SECRET_MOUNT_PATH=your-enabled-kv-secret-path-name
SECRET_PATH=path-to-kv-secret-to-accessed-for-key-value-pair-secrets

# Vault Transit secret configuration settings
TRANSIT_MOUNT_PATH=your-enabled-transit-secret-path
TRANSIT_KEY=path-to-transit-encryption-key-to-be-applied

echo "Applying target file/key presets for encryption/decryption operations..."

ORIGINAL_ENV_FILE=./secrets/encrypted-vault-credentials-env-file
SOPS_CONFIG_FILE=./sops/sops-configuration-filename
TEMP_ENV_FILE=./path/to/generated/temporary-env-file-containing-SOPS-encrypted-rekey-values
PGP_FINGERPRINT=fingerprint-of-pgp-key-to-be-used-to-encrypt-rekeyed-vault-credentials-env-file
TEMP_TEXT_FILE=./path/to/generated/temporary-text-file-containing-initial-pgp-encrypted-rekey-values

VAULT_JSON_FILE=./path/to/temporary/json/file/hold/encoded/rekey/values/as/json/objects
TMP_FILE=filename-of-temporary-SOPS-encryption-transfer-file

USERNAME=username-of-vault-user-to-have-updated-vault-token
PASS=password-of-vault-user-to-have-updated-vault-token

# Rekey vault unseal keys and rotate vault master key upon rekey verification.
# If successful, capture base64-encoded, pgp-encrypted unseal keys and dev user credentials for transcription to a temporary JSON file for process-isolated decryption and SOPS reencryption 
exp_envs="VAULT_ADDR=$VAULT_ADDR VAULT_PROXY_ADDR=$VAULT_PROXY_ADDR VAULT_SKIP_VERIFY=$VAULT_SKIP_VERIFY VAULT_CERT_PATH=$VAULT_CERT_PATH VAULT_CERT_KEY_PATH=$VAULT_CERT_KEY_PATH "
exp_envs+="GPG_HOME=$GPG_HOME UNSEAL_CRYPT_KEY1=$UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2=$UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3=$UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY=$TOKEN_CRYPT_KEY "
exp_envs+="ALT_UNSEAL_CRYPT_KEY1=$ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2=$ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3=$ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY=$ALT_TOKEN_CRYPT_KEY "
exp_envs+="SECRET_MOUNT_PATH=$SECRET_MOUNT_PATH SECRET_PATH=$SECRET_PATH TRANSIT_MOUNT_PATH=$TRANSIT_MOUNT_PATH TRANSIT_KEY=$TRANSIT_KEY "
exp_envs+="ORIGINAL_ENV_FILE=$ORIGINAL_ENV_FILE SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE TEMP_ENV_FILE=$TEMP_ENV_FILE PGP_FINGERPRINT=$PGP_FINGERPRINT TEMP_TEXT_FILE=$TEMP_TEXT_FILE "
exp_envs+="USERNAME=$USERNAME PASS=$PASS "
exp_envs+="python -m utils.rotate_vault_creds"

sops --config $SOPS_CONFIG_FILE exec-env $ORIGINAL_ENV_FILE "$exp_envs"


# Write the parsed PGP-encrypted unseal keys and vault user credentials values as a series of JSON objects to a new JSON file
echo "Attempting to parse encrypted vault credentials and write them as JSON objects within a temporary JSON file..."

python ./scripts/initialize/json_transcriber.py --input "$TEMP_TEXT_FILE" --output "$VAULT_JSON_FILE"

if [ $? -ne 0 ]; then
    echo "Parsing and/or writing of the encrypted unseal keys and vault user credentials to a new JSON file has failed."
    echo "Please ensure the local path to the file containing the encrypted vault data matches that used in 'json_transcriber.py'."
    kill -INT 0
fi


# Execute script for safely transferring decrypted vault authentication credentials values into a new environment file containing the reencrypted values using SOPS
exp_envs2+="ORIGINAL_ENV_FILE=$ORIGINAL_ENV_FILE SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE TEMP_ENV_FILE=$TEMP_ENV_FILE PGP_FINGERPRINT=$PGP_FINGERPRINT "
exp_envs2+="TEMP_TEXT_FILE=$TEMP_TEXT_FILE VAULT_JSON_FILE=$VAULT_JSON_FILE TMP_FILE=$TMP_FILE "
exp_envs2+="bash ./scripts/rotate/update_encrypted_keys.sh"

echo "Attempting to securely update and transfer the encrypted vault credentials values to a separate environment file using SOPS..."

sops --config $SOPS_CONFIG_FILE exec-env $ORIGINAL_ENV_FILE "$exp_envs2"

if [ $? -ne 0 ]; then
    echo "Reencryption or transfer of the vault credentials to a new environment file has failed."
    echo "Please ensure you have properly you have completed the SOPS installation/setup process detailed in the README file."
    kill -INT 0
fi

printf "Transfer of updated and now SOPS-encrypted vault credentials to file '%s' successful!\n" $TEMP_ENV_FILE

# Enforce owner-restricted read/write-only permissions for file storing encrypted variable values necessary to unseal and authenticate to the HashiCorp Vault server
echo "Attempting to update file permissions of final environment file containing SOPS-encrypted vault authentication values for enhanced security..."

chmod 600 "$ORIGINAL_ENV_FILE"

if [ $? -ne 0 ]; then
    echo "Updating file permissions for environment file containing SOPS-encrypted vault authentication keys failed."
    echo "You may need to execute this script with elevated permissions."
    kill -INT 0
fi

echo "Conducting final environment cleanup..."

rm -rf "$TEMP_TXT_FILE"
unset ORIGINAL_ENV_FILE SOPS_CONFIG_FILE TEMP_ENV_FILE PGP_FINGERPRINT TEMP_TXT_FILE VAULT_JSON_FILE USERNAME PASS
unset VAULT_ADDR VAULT_PROXY_ADDR VAULT_SKIP_VERIFY SECRET_MOUNT_PATH SECRET_PATH TRANSIT_MOUNT_PATH TRANSIT_KEY VAULT_CERT_PATH VAULT_CERT_KEY_PATH GPG_HOME
unset UNSEAL_CRYPT_KEY1 UNSEAL_CRYPT_KEY2 UNSEAL_CRYPT_KEY3 TOKEN_CRYPT_KEY ALT_UNSEAL_CRYPT_KEY1 ALT_UNSEAL_CRYPT_KEY2 ALT_UNSEAL_CRYPT_KEY3 ALT_TOKEN_CRYPT_KEY
echo "Cleanup Complete!"

history -c





