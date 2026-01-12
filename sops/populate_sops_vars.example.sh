export EXTERNAL_HOST=external-nginx-server-hostname
export EXTERNAL_PORT=external-nginx-server-port
export PGP_KEY_1_FINGERPRINT=pgp-encryption-key-1-fingerprint
export PGP_KEY_2_FINGERPRINT=pgp-encryption-key-2-fingerprint
export PGP_KEY_3_FINGERPRINT=pgp-encryption-key-3-fingerprint
export PGP_KEY_4_FINGERPRINT=pgp-encryption-key-4-fingerprint
export PGP_KEY_5_FINGERPRINT=pgp-encryption-key-5-fingerprint
export PGP_KEY_6_FINGERPRINT=pgp-encryption-key-6-fingerprint
export SOPS_CONFIG_FILENAME=sops-config-filename

env_sub_vars='${EXTERNAL_HOST} ${EXTERNAL_PORT} ${PGP_KEY_1_FINGERPRINT} ${PGP_KEY_2_FINGERPRINT} ${PGP_KEY_3_FINGERPRINT} '
env_sub_vars+='${PGP_KEY_4_FINGERPRINT} ${PGP_KEY_5_FINGERPRINT} ${PGP_KEY_6_FINGERPRINT}'

envsubst "$env_sub_vars" < ./sops/.sops.template.yaml > ./sops/${SOPS_CONFIG_FILENAME}

unset EXTERNAL_HOST EXTERNAL_PORT PGP_KEY_1_FINGERPRINT PGP_KEY_2_FINGERPRINT PGP_KEY_3_FINGERPRINT PGP_KEY_4_FINGERPRINT
unset PGP_KEY_5_FINGERPRINT PGP_KEY_6_FINGERPRINT SOPS_CONFIG_FILENAME