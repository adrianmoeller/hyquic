#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem"
CLIENT_ARGS="127.0.0.1 1234"

REPETITIONS=1
MODES=('kern' 'non' 'ext')

for cl_mode in "${MODES[@]}"; do
for sv_mode in "${MODES[@]}"; do
for ((i = 0 ; i < ${REPETITIONS} ; i++)); do
    ./single_benchmark.sh -s "${SERVER_ARGS}" -c "${CLIENT_ARGS}" -a "${cl_mode} ${sv_mode}" -q ${BUILD_DIR}/bandwidth
done
done
done
