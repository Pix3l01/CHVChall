#!/bin/bash
# Make sure the script runs with super user privileges.
[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"
# Load the kernel module.
modprobe vcan
# Create the virtual CAN interface.
ip link add dev vcan0 type vcan bitrate 50000 dbitrate 2000000
# Bring the virtual CAN interface online.
ip link set up vcan0

# To remove interface
# (sudo) ip link delete vcan0
