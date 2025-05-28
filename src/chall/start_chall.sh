modprobe vcan
ip link add dev vcan0 type vcan bitrate 50000 dbitrate 2000000
ip link set up vcan0

/usr/bin/python3 /chall/server.py

