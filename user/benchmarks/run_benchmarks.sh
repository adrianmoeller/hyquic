#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem"
CLIENT_ARGS="127.0.0.1 1234"

echo "./run_benchmark.sh -s '${SERVER_ARGS}' -c '${CLIENT_ARGS}' -a 'non non' ${BUILD_DIR}/bandwidth"
./run_benchmark.sh -s "${SERVER_ARGS}" -c "${CLIENT_ARGS}" -a "non non" ${BUILD_DIR}/bandwidth
echo Done