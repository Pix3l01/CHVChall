# Client for remote mirror

Simple client written in python to make a local linux socket-can interface communicate with the remote server mirror

## How to use it

You'll need `python3` and the `scapy` module (`pip install scapy`) to run it. To use it, you'll first need to setup your can interface or create a virtual one with this commands:

```bash
# Load kernel module
sudo modprobe vcan

# Create virtual interface
sudo ip link add dev vcan0 type vcan
# Enable interface
sudo ip link set up vcan0
# Delete interface
sudo ip link delete vcan0
```
Then run the script with: 

`python3 client.py vcan0` (or the name of your can interface) 

And you should be ready to go: all the messages sent on the CAN interface will be sent to the remote server and all the server replies will be sent on the CAN interface 

## How it communicates (if you need/want to implement your own)

It creates a TCP socket to the server (`10.0.0.2:4000`)

Once a client connects, the server sends an hexencoded hello message. After that, the communication can start

Only the hexencoded UDS payloads are exchanged (no CAN and ISOTP layers), so you can only communicate through the UDS IDs (which is all you need to solve the challenge)

The end of a message (which can be longer than a single CAN frame) is identified by a new line character (`\n`), if you are implementing you onw client remember to send it, otherwise the server won't reply

To test the raw TCP communication you can connect straight to the server with `netcat` (`nc 10.0.0.2 4000`), send a simple hexencoded UDS message like the DSC in session 0x1 (`1001`), press enter, and you should get the reply from the server