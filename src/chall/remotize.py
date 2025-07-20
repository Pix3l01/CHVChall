import logging
import threading

from scapy.contrib.cansocket_native import CANSocket
from scapy.layers.can import CAN
from scapy.packet import Raw

from server import main, handle_packet

IFACE = 'vcan0'
READ_ID = 0x7b0

def write_to_can(packet):
    if packet[CAN].identifier == READ_ID:
        print(bytes(packet).hex())

def sender_thread():
    CANSocket(IFACE).sniff(prn=write_to_can)

if __name__ == '__main__':
    logger = logging.getLogger('can2stream')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.info('Starting UDS server')
    threading.Thread(target=main, daemon=True).start()

    logger.info("Starting thread to read from CAN interface and printing to stdout")
    threading.Thread(target=sender_thread, daemon=True).start()

    logger.info("Starting thread to send stdin to CAN interface")
    while True:
        a = input()
        try:
            pkt = CAN() / Raw(bytes.fromhex(a))
            handle_packet(pkt)
        except Exception as e:
            logger.exception(e)
