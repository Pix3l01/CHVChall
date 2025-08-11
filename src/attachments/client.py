import socket
import sys
import threading

from scapy.contrib.automotive.uds import UDS
from scapy.contrib.isotp import ISOTPNativeSocket

IP = '52.9.34.196'
PORT = 9999
tcp_sock = None

def send_to_server(packet):
        tcp_sock.sendall(bytes(packet).hex().encode() + b'\n')
        
def tcp_listener():
    try:
        while True:
            data = b''
            while b'\n' not in data:
                data += tcp_sock.recv(4096)

            # Send received data over CAN
            if data == b'0068656c6c6f\r\n':
                print("Communicaion established, ready to proxy the CAN interface")
            elif data.strip() != b'':
                try: 
                    can_sock.send(UDS(bytes.fromhex(data.decode().strip())))
                # If something happens don't crash. Shouldn't be a big problem (?)
                except Exception as e:
                    pass

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
        tcp_sock.connect((IP, PORT))
        print(f"Connected to {IP}:{PORT}")
    except Exception as e:
        print("Failed to connect to server:", e)
        sys.exit(1)

    can_sock = ISOTPNativeSocket(iface, 0x742, 0x769, basecls=UDS)
    # Start TCP listener thread
    t = threading.Thread(target=tcp_listener, daemon=True)
    t.start()
    
    can_sock.sniff(prn=send_to_server)