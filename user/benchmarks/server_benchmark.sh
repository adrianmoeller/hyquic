#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem"
CLIENT_ARGS="127.0.0.1 1234"

${BUILD_DIR}/bandwidth server ${SERVER_ARGS} $1