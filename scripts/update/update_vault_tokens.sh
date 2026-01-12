#!/usr/bin/env bash

set +o history

# Append 'VAULT_TOKEN' env variable with the decrypted not-root user token to the SOPS-generated temporary file  
echo 'VAULT_TOKEN=your-user-token' >> $TMPFILE

# Pass the decrypted vault environment variable values from temporary file to SOPS over STDIN (ensures variables only exist in memory)
# for writing the reencrypted values to new permanent file within the 'secrets' directory 
cat $TMPFILE | sops --config $SOPS_CONFIG_FILE encrypt --filename-override=$EXTENDED_VAULT_ENV_FILE --pgp $EXTENDED_ENV_ENC_FINGERPRINT --input-type=dotenv > "$EXTENDED_VAULT_ENV_FILE"
history -c
exit