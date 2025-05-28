import queue, threading

from scapy.contrib.automotive.uds import UDS, UDS_NR

import config
import global_stuff as gl
from services_handler import *

handlers = {0x10: disgnostic_session_control,
            0x11: ecu_reset,
            0x22: read_data_by_identifier,
            0x23: read_memory_by_address,
            0x27: security_access, 
            0x3e: tester_present}
q = queue.Queue(config.QUEUE_SIZE)

"""
def send(pkt):
    SOCK.send(pkt)
"""
def worker():
    while True:
        pkt = q.get()
        try:
            handlers[pkt[UDS].service](pkt)
        except:
            sock = ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False)
            sock.send(UDS()/UDS_NR( requestServiceId=pkt[UDS].service, negativeResponseCode=0x11))
            sock.close()
        q.task_done()

def inactivity():
    while True:
        if gl.CURRENT_SESSION != 1 and not gl.BUSY:
            time.sleep(1)
            gl.TIME_ELAPSED += 1
            if gl.TIME_ELAPSED > config.SESSION_RESET_TIMEOUT:
                gl.CURRENT_SESSION = 1
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
        pkt = UDS()/UDS_NR( requestServiceId=pkt[UDS].service, negativeResponseCode=0x11)
        sock = ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False)
        sock.send(pkt)
        sock.close()

config.generate_memory()
threading.Thread(target=worker, daemon=True).start()
threading.Thread(target=inactivity, daemon=True).start()
ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False).sniff(prn= handle_packet)
