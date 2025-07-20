#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <remote|local> <can_interface>"
    exit 1
fi

export IFACE=$2

if [ "$1" == "remote" ]; then
    echo "Running chal in remote mode"
    # TODO add timeout
    socat TCP-LISTEN:4000,reuseaddr,fork EXEC:"python3 remotize.py",pty,echo=0
elif [ "$1" == "local" ]; then
    echo "Running chall in local mode"
    python3 server.py
else
    echo "Invalid option. Use 'remote' or 'local'."
    exit 2
fi