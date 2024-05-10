#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem"
CLIENT_ARGS="127.0.0.1 1234"

REPETITIONS=10
MODES=('kern' 'non' 'ext')

echo "peer,kbyte_per_sec"
for client_mode in "${MODES[@]}"; do
for ((i = 0 ; i < ${REPETITIONS} ; i++)); do
    echo "${client_mode},$(${BUILD_DIR}/bandwidth client ${CLIENT_ARGS} ${client_mode})"
done
done
