import logging
import threading

from scapy.contrib.automotive.uds import UDS

from scapy.packet import Raw

from server import main, handle_packet

IFACE = 'vcan0'
READ_ID = 0x7b0

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


    logger.info("Ready to send stdin to CAN interface")
    while True:
        a = input()
        try:
            pkt = UDS(bytes.fromhex(a))
            handle_packet(pkt)
        except Exception as e:
            logger.exception(e)
