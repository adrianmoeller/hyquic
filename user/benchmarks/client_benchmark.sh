#!/bin/bash

THIS_DIR=$(dirname "$0")
BUILD_DIR=${THIS_DIR}/../build
KEYS_DIR=${THIS_DIR}/../tests/keys
SERVER_ARGS="-k ${KEYS_DIR}/server-key-u.pem -c ${KEYS_DIR}/server-cert-u.pem"
# CLIENT_ARGS="-a 127.0.0.1"
CLIENT_ARGS="-a 127.0.0.1 -k ${KEYS_DIR}/client-psk.txt"

REPETITIONS=10
CLIENT_MODES=('kern' 'non' 'inj' 'ext')
SERVER_MODE=""
LOSS=""
INJ_SWEEP=""
BUFF_SWEEP=""

while getopts "r:m:l:ib:" opt; do
    case ${opt} in
        r)
            REPETITIONS=${OPTARG}
            ;;
        m)
            SERVER_MODE=${OPTARG}
            ;;
        l)
            LOSS=${OPTARG}
            ;;
        i)
            INJ_SWEEP="1"
            ;;
        b)
            BUFF_SWEEP=${OPTARG}
            ;;
        ?)
            exit 1
            ;;
    esac
done

if [[ -n ${LOSS} ]]; then
    echo "  add loss ${LOSS}"
    tc qdisc add dev lo root netem loss ${LOSS}
    trap "echo '  remove loss ${LOSS}'; tc qdisc del dev lo root netem loss ${LOSS}; exit 1" SIGINT
fi

if [[ -n ${INJ_SWEEP} ]]; then
    echo "server_mode,inj_ratio,kbyte_per_sec,sender_kbyte_per_sec"
    for ((i = 0 ; i <= 10 ; i++)); do
    for ((j = 0 ; j < ${REPETITIONS} ; j++)); do
        echo "${SERVER_MODE},${i},$(${BUILD_DIR}/bandwidth ${CLIENT_ARGS} -m inj -i ${i})"
    done
    done
elif [[ -n ${BUFF_SWEEP} ]]; then
    echo "server_mode,buff_size,kbyte_per_sec,sender_kbyte_per_sec"
    for ((i = 256 ; i <= 16384 ; i *= 2)); do
    for ((j = 0 ; j < ${REPETITIONS} ; j++)); do
        echo "${SERVER_MODE},${i},$(${BUILD_DIR}/bandwidth ${CLIENT_ARGS} -m ${BUFF_SWEEP} -b ${i})"
    done
    done
else
    echo "server_mode,client_mode,kbyte_per_sec,sender_kbyte_per_sec"
    for client_mode in "${CLIENT_MODES[@]}"; do
    for ((i = 0 ; i < ${REPETITIONS} ; i++)); do
        if [[ -n ${LOSS} ]]; then
            echo "${SERVER_MODE},${client_mode},$(${BUILD_DIR}/bandwidth ${CLIENT_ARGS} -m ${client_mode} -t 134217728)" # 128 * 1024 * 1024
        else
            echo "${SERVER_MODE},${client_mode},$(${BUILD_DIR}/bandwidth ${CLIENT_ARGS} -m ${client_mode})"
        fi
    done
    done

    if [[ -n ${LOSS} ]]; then
        echo "  remove loss ${LOSS}"
        tc qdisc del dev lo root netem loss ${LOSS}
    fi
fi