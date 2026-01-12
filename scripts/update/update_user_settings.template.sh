#!/usr/bin/env bash


echo "Applying Vault server configuration environment variables..."
export VAULT_ADDR=${VAULT_ADDR}
export VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY}

# Filenames/paths settings
echo "Applying target file/key presets for encryption/decryption operations..."
ORIGINAL_VAULT_ENV_FILE=${ORIGINAL_VAULT_ENV_FILE}
EXTENDED_VAULT_ENV_FILE=${EXTENDED_VAULT_ENV_FILE}
EXTENDED_ENV_ENC_FINGERPRINT=${EXTENDED_ENV_ENC_FINGERPRINT}
SOPS_CONFIG_FILE=${SOPS_CONFIG_FILE}

# Spawn a child process using sops exec-file to pass the decrypted contents to the script as a temporary file
printf "Attempting to generate updated environment file at '%s'...\n" "$EXTENDED_VAULT_ENV_FILE"

env_vars="TMPFILE={} EXTENDED_VAULT_ENV_FILE=$EXTENDED_VAULT_ENV_FILE EXTENDED_ENV_ENC_FINGERPRINT=$EXTENDED_ENV_ENC_FINGERPRINT SOPS_CONFIG_FILE=$SOPS_CONFIG_FILE " 
env_vars+="bash ./scripts/update/update_vault_tokens.sh"

sops --config $SOPS_CONFIG_FILE exec-file --no-fifo "$ORIGINAL_VAULT_ENV_FILE"  "$env_vars"
if [ $? -ne 0 ]; then
    echo "Generation of environment file with updated non-root user token failed"
    echo "Please ensure the SOPS has been properly installed and configured for local use and the assigned environment variables are valid values" 
    kill -INT 0
fi


# Update file permissions to read/write restricted to owner only for updated environment file containing encrypted vault credentials
echo "Attempting to update file permissions of update environment file..."
chmod 600 "$EXTENDED_VAULT_ENV_FILE"

if [ $? -ne 0 ]; then
    printf "Updating file permissions for file containing updated SOPS-encrypted vault authentication credentials failed."
    echo "You may need to execute this script with elevated permissions."
    kill -INT 0
fi


printf "Generation of update environment file with encrypted vault credentials at '%s' complete!\n" "$EXTENDED_VAULT_ENV_FILE"

# Unset all defined environment variables 
echo "Completing environment cleanup..."

unset VAULT_ADDR VAULT_SKIP_VERIFY ORIGINAL_VAULT_ENV_FILE EXTENDED_VAULT_ENV_FILE EXTENDED_ENV_ENC_FINGERPRINT

echo "Cleanup complete!"