#!/bin/bash

set -e
make module
sudo make module_install
make
sudo make install

echo -n "Run tests? [y/n]: "
read -r ans
if [[ "$ans" == "y" ]]; then
    cd tests/
    sudo make run
fi