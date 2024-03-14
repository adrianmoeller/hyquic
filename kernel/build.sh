#!/bin/bash

set -e

CONFIG_ENABLED=0
TESTS_ENABLED=0

while getopts "ct" opt; do
    case ${opt} in
        c)
            CONFIG_ENABLED=1
            ;;
        t)
            TESTS_ENABLED=1
            ;;
    esac
done

if [[ "${CONFIG_ENABLED}" == "1" ]]; then
    echo "<CONFIGURE>"
    echo
    ./autogen.sh
    ./configure --prefix=/usr
    echo
fi

echo "<BUILD>"
echo

make module
sudo make module_install
make
sudo make install

if [[ "${TESTS_ENABLED}" == "1" ]]; then
    echo
    echo "<RUN TESTS>"
    echo
    cd tests/
    sudo make run
fi