import queue
import time
import threading

from scapy.contrib.isotp import ISOTPNativeSocket
from scapy.contrib.automotive.uds import UDS, UDS_NR
from scapy.packet import Raw

from classes import LocalSocket
import config
import global_stuff as gl
from services_handler import diagnostic_session_control, ecu_reset, read_data_by_identifier, read_memory_by_address, \
    security_access, write_data_by_identifier, tester_present

if config.IFACE == 'remote':
    sock = LocalSocket()
else:
    sock = ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False)

handlers = {0x10: diagnostic_session_control,
            0x11: ecu_reset,
            0x22: read_data_by_identifier,
            0x23: read_memory_by_address,
            0x27: security_access,
            0x2E: write_data_by_identifier,
            0x3e: tester_present}
q = queue.Queue(config.QUEUE_SIZE)


def worker():
    while True:
        pkt = q.get()
        try:
            handlers[pkt[UDS].service](pkt, sock)
        except Exception as e:
            gl.logger.debug(repr(e))
            sock.send(UDS() / UDS_NR(requestServiceId=pkt[UDS].service, negativeResponseCode=0x11))
        q.task_done()


def inactivity():
    while True:
        if config.get_session() != 1 and not gl.BUSY:
            time.sleep(1)
            gl.TIME_ELAPSED += 1
            if gl.TIME_ELAPSED > config.SESSION_RESET_TIMEOUT:
                gl.logger.info("Session timed out. Resetting session.")
                config.set_session(b'\x01')
                gl.AUTH = False
                gl.TIME_ELAPSED = 0
        else:
            time.sleep(0.1)


def handle_packet(pkt):
    gl.TIME_ELAPSED = 0
    if pkt[UDS].service in config.SUPPORTED_SERVICES:
        try:
            q.put(pkt, block=False)
        except queue.Full:
            return
    else:
        pkt = UDS() / UDS_NR(requestServiceId=pkt[UDS].service, negativeResponseCode=0x11)
        sock.send(pkt)


def main():
    gl.logger.info("Starting server...")
    config.generate_memory()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=inactivity, daemon=True).start()
    if config.IFACE != 'remote':
        ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False).sniff(
            prn=handle_packet)
    sock.send(UDS()/Raw(b'hello'))

if __name__ == '__main__':
    main()
