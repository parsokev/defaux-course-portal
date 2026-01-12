#!/usr/bin/env bash

export APP_PORT=8500
export VAULT_PORT=8200

envsubst '${APP_PORT} ${VAULT_PORT}' < ./nginx/production.template.conf > ./nginx/production.conf
envsubst '${VAULT_PORT}' < ./nginx/development.vault.template.conf > ./nginx/development.vault.conf


unset APP_PORT VAULT_PORT