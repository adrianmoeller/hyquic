#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="0.0.0.0 1234 ${KEYS_DIR}/server-key-u.pem ${KEYS_DIR}/server-cert-u.pem"
CLIENT_ARGS="127.0.0.1 1234"


./single_benchmark.sh -s "${SERVER_ARGS}" -c "${CLIENT_ARGS}" -a "ext ext" ${BUILD_DIR}/bandwidth
