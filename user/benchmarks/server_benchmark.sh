#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
#SERVER_ARGS="-k ${KEYS_DIR}/server-key-u.pem -c ${KEYS_DIR}/server-cert-u.pem"
SERVER_ARGS="-k ${KEYS_DIR}/server-psk.txt"
CLIENT_ARGS="-a 127.0.0.1"
SERVER_MODE=""

while getopts "m:" opt; do
    case ${opt} in
        m)
            SERVER_MODE=${OPTARG}
            ;;
        ?)
            exit 1
            ;;
    esac
done

${BUILD_DIR}/bandwidth -s ${SERVER_ARGS} -m ${SERVER_MODE}
