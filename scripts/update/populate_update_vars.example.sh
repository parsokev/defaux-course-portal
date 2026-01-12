#!/usr/bin/env bash

export VAULT_ADDR="https://your-domain:your-port"
export VAULT_SKIP_VERIFY=true
export ORIGINAL_VAULT_ENV_FILE=./secrets/your-original-env-file.env
export EXTENDED_VAULT_ENV_FILE=./secrets/your-updated-env-file.env
export EXTENDED_ENV_ENC_FINGERPRINT=your-chosen-pgp-fingerprint
export SOPS_CONFIG_FILE=path/to/your/sops/config/file

env_sub_vars='${VAULT_ADDR} ${VAULT_SKIP_VERIFY} ${ORIGINAL_VAULT_ENV_FILE} ${EXTENDED_VAULT_ENV_FILE} ${EXTENDED_ENV_ENC_FINGERPRINT} ${SOPS_CONFIG_FILE}'

envsubst "$env_sub_vars" < ./scripts/update/update_user_settings.template.sh > ./scripts/update/update_user_settings.sh

unset VAULT_ADDR VAULT_SKIP_VERIFY ORIGINAL_VAULT_ENV_FILE EXTENDED_VAULT_ENV_FILE EXTENDED_ENV_ENC_FINGERPRINT SOPS_CONFIG_FILE