#!/bin/bash

YELLOW='\033[1;33m'
NC='\033[0m'
EXIT_CODE=0
THIS_DIR=$(dirname "$0")
ADDITIONAL_ARGS=''
TEMP_FILE=${THIS_DIR}/../build/benchmark.tmp

while getopts "s:c:a:q" opt; do
    case ${opt} in
        s)
            SERVER_ARGS=${OPTARG}
            ;;
        c)
            CLIENT_ARGS=${OPTARG}
            ;;
        a)
            ADDITIONAL_ARGS=${OPTARG}
            ;;
        ?)
            exit 1
            ;;
    esac
done

[ "${SERVER_ARGS}" != "" ] || exit 1
[ "${CLIENT_ARGS}" != "" ] || exit 1

shift $(($OPTIND - 1))
[ "$@" != "" ] || exit 1

APP_EXEC="${THIS_DIR}/../build/$@"

rm -f ${TEMP_FILE}
timeout -k 20s 240s ${APP_EXEC} server ${SERVER_ARGS} ${ADDITIONAL_ARGS} &> ${TEMP_FILE} &
SERVER_PID=$!
trap "kill ${SERVER_PID}; exit ${EXIT_CODE}" SIGINT
sleep 1

echo -e "${YELLOW}<Client>${NC}"
${APP_EXEC} client ${CLIENT_ARGS} ${ADDITIONAL_ARGS}
CLIENT_EXIT_CODE=$?
[ "${CLIENT_EXIT_CODE}" != "0" ] && EXIT_CODE=${CLIENT_EXIT_CODE}
sleep 3

echo
echo -e "${YELLOW}<Server>${NC}"

pkill ${SERVER_PID}
sleep 1

cat ${TEMP_FILE}

exit ${EXIT_CODE}