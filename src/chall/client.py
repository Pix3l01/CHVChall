import socket
import sys
import threading

from scapy.contrib.automotive.uds import UDS
from scapy.contrib.isotp import ISOTPNativeSocket

IP = '127.0.0.1'
tcp_sock = None

def send_to_server(packet):
        print("Send to server:" + bytes(packet).hex())
        tcp_sock.sendall(bytes(packet).hex().encode())
        
def tcp_listener():
    try:
        while True:
            data = tcp_sock.recv(4096)
            if not data:
                print("Disconnected from server.")
                break
            print("Received from server:", data)

            # Send received data over CAN
            if data != b'0068656c6c6f\r\n':
                can_sock.send(UDS(bytes.fromhex(data.decode().strip())))
    except Exception as e:
        print("TCP listener error:", e)
    finally:
        tcp_sock.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 %s <can_interface>' % sys.argv[0])
        exit(1)

    iface = sys.argv[1]
    # Setup TCP connection to server
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_sock.connect(('127.0.0.1', 4000))
        print("Connected to 127.0.0.1:4000")
    except Exception as e:
        print("Failed to connect to server:", e)
        sys.exit(1)

    can_sock = ISOTPNativeSocket(iface, 0x7b0, 0x7d0, basecls=UDS)
    # Start TCP listener thread
    t = threading.Thread(target=tcp_listener, daemon=True)
    t.start()
    
    can_sock.sniff(prn=send_to_server)