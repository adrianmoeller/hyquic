#!/bin/bash

YELLOW='\033[1;33m'
NC='\033[0m'
EXIT_CODE=0

while getopts "s:c:" opt; do
    case ${opt} in
        s)
            SERVER_ARGS=${OPTARG}
            ;;
        c)
            CLIENT_ARGS=${OPTARG}
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

APP_EXEC="./$@"

rm -f test.tmp
timeout -k 20s 20s ${APP_EXEC} -- server ${SERVER_ARGS} &> test.tmp &
SERVER_PID=$!
trap "kill ${SERVER_PID}; exit ${EXIT_CODE}" SIGINT
sleep 1

echo -e "${YELLOW}<Client>${NC}"
${APP_EXEC} -- client ${CLIENT_ARGS}
CLIENT_EXIT_CODE=$?
[ "${CLIENT_EXIT_CODE}" != "0" ] && EXIT_CODE=${CLIENT_EXIT_CODE}

echo
echo -e "${YELLOW}<Server>${NC}"

wait ${SERVER_PID}
SERVER_EXIT_CODE=$?
[ "${SERVER_EXIT_CODE}" != "0" ] && EXIT_CODE=${SERVER_EXIT_CODE}
sleep 1

cat test.tmp

exit ${EXIT_CODE}