#!/usr/bin/env bash

set +o history
# Create temporary directory and file for transferring decrypted data using mktemp to apply random generation
# to naming and restrictive permisions to enhance file security (https://stackoverflow.com/questions/10982911/creating-temporary-files-in-bash)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp/}$(basename $0).XXXXXXXXXXXX")

FULL_PATH="$TMP_DIR/$TMP_FILE"
touch $FULL_PATH

# Parse key:value pairs from intermediate JSON file, where each key's value is base-64 encoded and encrypted with a unique PGP key
while IFS="" read -r p || [ -n "$p" ]
do
  ENV_KEY=$(jq -r .name <<< "$p" 2>/dev/null)
  ENC_VALUE=$(jq -r .value <<< "$p" 2>/dev/null)
  DEC_VALUE=$(echo $ENC_VALUE | base64 --decode | gpg -dq) # Decrypted decoded value with appropriate PGP key using GnuPG
  echo "$ENV_KEY=$DEC_VALUE" >> $FULL_PATH # Write to temporary file env file
done < "$VAULT_JSON_FILE"
cat $FULL_PATH | sops --config $SOPS_CONFIG_FILE encrypt --filename-override=$TEMP_ENV_FILE  --pgp $PGP_FINGERPRINT > "$TEMP_ENV_FILE"

# Cleanup intermediate/temporary files and clear logs
cat $TEMP_ENV_FILE > $ORIGINAL_ENV_FILE

rm -rf $TMP_DIR
rm -rf $VAULT_JSON_FILE
rm -rf $TEMP_TEXT_FILE
rm -rf $TEMP_ENV_FILE

history -c