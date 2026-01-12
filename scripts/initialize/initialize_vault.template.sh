#!/usr/bin/env bash

# #################################### Vault Initializaton #############################################
#
# 1. Intializes the Vault server using GPG-mediated PGP encryption:
#
#  - Encrypts unseal key #1, unseal key #2, and unseal key #3 with 'pbkp1', ' pbkp2', and 'pbkp3' GPG keys, respectively
#  - Encrypts the root token using the 'pbkp4' GPG key
#
# 2. Writes the encrypted keys and root token valus written to STDOUT to the file '.vault-keys.b64.enc.txt'
#    within the 'secrets' directory
#
# 3. Changes file permisions for './secrets/.vault-keys.b64.enc.txt' to only be read by current user
#
# 4. Executes python script that parses the encrypted unseal keys and root token from './secrets/.vault-keys.b64.enc.txt'
#    and writes them in the JSON file './secrets/.vault-creds.json'
#    
#   - Assigns the parsed key:value pairs in their expected order of appearance from the generated vault initialization output
#   - From first to last in order of appearance:`UNSEAL_KEY_1`, `UNSEAL_KEY_2`, `UNSEAL_KEY_3`, and `ROOT_TOKEN` 
#   
# 5. Executes shell script that decrypts the base64-encoded, PGP-encrypted values and reencrypts them using
#    a SOPS-assigned PGP key within a separate shell process (to enable isolated extraction of encrypted values
#    using SOPS-provided file metadata)
#
#  6. At the completion of script execution, the PGP-encrypted file containing the unseal keys and root token
#     should now be located within the '/secrets/.vault-creds.enc.env' file. Now, SOPS can securely extract
#     the decrypted unseal key or root token values for use in unsealing the vault
#
# #######################################################################################################

echo "Applying Vault server configuration environment variables..."
export VAULT_ADDR=${VAULT_ADDR}
export VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY}
export VAULT_CLUSTER_ADDR=${VAULT_CLUSTER_ADDR}

echo "Applying target file/key presets for encryption/decryption operations..."
# Filenames/paths settings
VAULT_TEXT_FILE=${VAULT_TEXT_FILE}
VAULT_JSON_FILE=${VAULT_JSON_FILE}
VAULT_ENV_FILE=${VAULT_ENV_FILE}
TMP_FILE=${TMP_FILE}
SOPS_CONFIG_FILE=${SOPS_CONFIG_FILE}

# PGP-encryption file settings
PGP_KEY_1_FILE=${PGP_KEY_1_FILE}
PGP_KEY_2_FILE=${PGP_KEY_2_FILE}
PGP_KEY_3_FILE=${PGP_KEY_3_FILE}
PGP_KEY_4_FILE=${PGP_KEY_4_FILE}
ENV_ENC_FINGERPRINT=${ENV_ENC_FINGERPRINT}

# Initalize Vault using provided paths to local to base64-encoded/binary files of PGP encryption keys 
echo "Initializing Vault Server instance using provided local paths to encryption key files..."

vault operator init -key-shares=3 -key-threshold=2 \
    -pgp-keys="$PGP_KEY_1_FILE,$PGP_KEY_2_FILE,$PGP_KEY_3_FILE" \
    -root-token-pgp-key="$PGP_KEY_4_FILE" \
    > "$VAULT_TEXT_FILE"

if [ $? -ne 0 ]; then
    echo "Vault initialization failed."
    echo "Please ensure you have provided a valid relative path from the project's root directory to each existing encryption key you wish to use."
    printf "If you are attempting to reinitialize a new vault instance with a pre-existing vault key plaintext file at '%s', you must delete this file first\n" ${VAULT_TEXT_FILE}
    echo "Please review the project documentation at https://github.com/parsokev/defaux-course-portal for additional information."
    kill -INT 0
fi
printf "Vault server instance successfully initialized!\n\n"



# Enforce owner-restricted read-only permissions for file containing the provided plaintext values of the encrypted unseal keys and root token
echo "Attempting to update file permissions of file containing encrypted vault authentication values for enhanced security..."

chmod 400 "$VAULT_TEXT_FILE"

if [ $? -ne 0 ]; then
    printf "Updating file permissions for file containing initial encrypted vault authentication keys failed."
    echo "You may need to execute this script with elevated permissions."
    kill -INT 0
fi


# Write the parsed PGP-encrypted unseal keys and initial root token values as a series of JSON objects to a new JSON file
echo "Attempting to parse encrypted unseal keys and root token and write them as JSON objects within a temporary JSON file..."

python ./scripts/initialize/json_transcriber.py --input "$VAULT_TEXT_FILE" --output "$VAULT_JSON_FILE"

if [ $? -ne 0 ]; then
    echo "Parsing of encrypted unseal keys and root token or writing these parsed values to a new JSON file has failed."
    echo "Please ensure the local path to the file containing the encrypted unseal keys and root token matches that used in 'json_transcriber.py'."
    kill -INT 0
fi


# Execute script for safely transferring decrypted vault initialization values into a new environment file containing the reencrypted values using SOPS
echo "Attempting to securely update and transfer the encrypted vault values to a separate environment file using SOPS..."
# env_vars="SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE VAULT_ENV_FILE=$VAULT_ENV_FILE VAULT_JSON_FILE=$VAULT_JSON_FILE TMP_FILE=$TMP_FILE "
# env_vars+="ENV_ENC_FINGERPRINT=$ENV_ENC_FINGERPRINT bash ./scripts/initialize/sops_exchange.sh"

SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE VAULT_ENV_FILE=$VAULT_ENV_FILE VAULT_JSON_FILE=$VAULT_JSON_FILE TMP_FILE=$TMP_FILE ENV_ENC_FINGERPRINT=$ENV_ENC_FINGERPRINT bash ./scripts/initialize/sops_exchange.sh

if [ $? -ne 0 ]; then
    echo "Reencryption or transfer of the vault unseal keys and/or root token to a new environment file has failed."
    echo "Please ensure you have properly you have completed the SOPS installation/setup process detailed in the README file."
    kill -INT 0
fi

# Enforce owner-restricted read/write-only permissions for file storing encrypted variable values necessary to unseal and authenticate to the HashiCorp Vault server
echo "Attempting to update file permissions of environment file containing SOPS-encrypted vault authentication values for enhanced security..."

chmod 600 "$VAULT_ENV_FILE"

if [ $? -ne 0 ]; then
    echo "Updating file permissions for environment file containing SOPS-encrypted vault authentication keys failed."
    echo "You may need to execute this script with elevated permissions."
    kill -INT 0
fi

printf "Transfer of SOPS-encrypted vault unseal keys and root token to file '%s' successful!\n" $VAULT_ENV_FILE

echo "Finishing environment cleanup..."

unset VAULT_PORT VAULT_CLUSTER_PORT VAULT_HOSTNAME VAULT_ADDR VAULT_CLUSTER_ADDR VAULT_SKIP_VERIFY VAULT_CERT_FILENAME VAULT_CERT_KEY_FILENAME
unset VAULT_TEXT_FILE VAULT_JSON_FILE VAULT_ENV_FILE TMP_FILE PGP_KEY_1_FILE PGP_KEY_2_FILE PGP_KEY_3_FILE PGP_KEY_4_FILE 
unset ENV_ENC_FINGERPRINT SOPS_CONFIG_FILE
unset VAULT_ADDR VAULT_SKIP_VERIFY VAULT_TEXT_FILE VAULT_JSON_FILE VAULT_ENV_FILE TMP_FILE PGP_KEY_1_FILE PGP_KEY_2_FILE PGP_KEY_3_FILE PGP_KEY_4_FILE ENV_ENC_FINGERPRINT

echo "Cleanup Complete!"