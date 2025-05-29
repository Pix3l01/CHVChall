import time

from scapy.contrib.automotive.uds import UDS, UDS_NR
from scapy.packet import Raw

from scapy.contrib.isotp import ISOTPNativeSocket

import config
import global_stuff as gl
from classes import SA_seed

def send_msg(pkt):
    sock = ISOTPNativeSocket(config.IFACE, config.TX_ID, config.RX_ID, basecls=UDS, padding=True, fd=False)
    sock.send(pkt)
    sock.close()


def tester_present(pkt):
    from scapy.contrib.automotive.uds import UDS_TPPR
    gl.TIME_ELAPSED = 0
    send_msg(UDS()/UDS_TPPR()) 

def disgnostic_session_control(pkt):
    from scapy.contrib.automotive.uds import UDS_DSC, UDS_DSCPR

    new_session = pkt[UDS][UDS_DSC].diagnosticSessionType
    # If new session is the same as the current one do nothing, just reply with positive response
    if new_session == gl.CURRENT_SESSION:
        send_msg(UDS()/UDS_DSCPR(diagnosticSessionType=gl.CURRENT_SESSION))
        return

    # Check whther the new session is accessible from the current one
    if new_session in config.ACCESSIBLE_SESSIONS[gl.CURRENT_SESSION]:
        # Simulate bootloader switch when cheanging from/to session 2
        if new_session == 2 or gl.CURRENT_SESSION == 2:
            gl.BUSY = True
            start = time.time()
            while time.time() - start < config.BOOTLOADER_SWITCH_TIMEOUT:
                send_msg(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x78))
                gl.TIME_ELAPSED = 0 
                time.sleep(1)
            gl.BUSY = False
                     
        gl.CURRENT_SESSION = new_session
        config.DATA_IDs[61746] = (int.to_bytes(gl.CURRENT_SESSION, 1, "big"), False, False)
        gl.AUTH = False
        send_msg(UDS()/UDS_DSCPR(diagnosticSessionType=gl.CURRENT_SESSION))
    elif new_session in config.DSC_SESSIONS:
        # Session exists but is not accessible from the current one
        send_msg(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x22))
    else:
        # Session does not exist
        send_msg(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x12))

def read_data_by_identifier(pkt):
    from scapy.contrib.automotive.uds import UDS_RDBI, UDS_RDBIPR
    did = pkt[UDS][UDS_RDBI].identifiers[0]
    #session_did = config.DATA_ID[gl.CURRENT_SESSION]
    if did in config.DIDs_PER_SESSION[gl.CURRENT_SESSION]:
        # If d_id can be read without auth
        session_did = config.DATA_IDs[did]
        if not session_did[1]:
            # session_did[did][0]
            send_msg(UDS()/UDS_RDBIPR(dataIdentifier=did)/Raw(session_did[0]))
            return
        elif session_did[1] and gl.AUTH:
            send_msg(UDS()/UDS_RDBIPR(dataIdentifier=did)/Raw(session_did[0]))
        else:
            send_msg(UDS()/UDS_NR(requestServiceId=0x22, negativeResponseCode=0x33))
    else:
        send_msg(UDS()/UDS_NR(requestServiceId=0x22, negativeResponseCode=0x31))

def security_access(pkt):
    from scapy.contrib.automotive.uds import UDS_SA, UDS_SAPR
    security_level = pkt[UDS][UDS_SA].securityAccessType

    if gl.SEND_ENOA:
        if time.time() - gl.TIME_ENOA_ACTIVATED > config.SEED_REQUEST_TIMEOUT:
            gl.SEND_ENOA = False
            gl.TIME_ENOA_ACTIVATED = 0
            gl.RETRIES = 0
        else:
            send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x36))    
            return

    if gl.CURRENT_SESSION not in config.SECURITY_ACCESS_LEVELS:
        send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x7F))
        return

    if security_level % 2 == 0:
        if security_level - 1 not in config.SECURITY_ACCESS_LEVELS[gl.CURRENT_SESSION]:
            send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x12))
            gl.SEED = None
            return
        
        if gl.SEED is None:
            send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x24))
            return
        
        if config.key_check(pkt[UDS][UDS_SA].securityKey, security_level):
            gl.RETRIES = 0
            gl.AUTH = True
            gl.SEED = None
            send_msg(UDS()/UDS_SAPR(securityAccessType=security_level))
        else:
            gl.SEED = None
            gl.RETRIES += 1
            if gl.RETRIES >= config.SEED_REQUEST_RETRIES:
                gl.SEND_ENOA = True
                gl.TIME_ENOA_ACTIVATED = time.time()
            send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x35))
    else:
        if security_level not in config.SECURITY_ACCESS_LEVELS[gl.CURRENT_SESSION]:
            send_msg(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x12))
            return
        if gl.SEED is None or not gl.SEED.is_valid() or gl.SEED.level != security_level:
            gl.SEED = SA_seed(security_level)
        send_msg(UDS()/UDS_SAPR(securityAccessType=security_level, securitySeed=gl.SEED.seed))

def ecu_reset(pkt):
    from scapy.contrib.automotive.uds import UDS_ER, UDS_ERPR
    if gl.CURRENT_SESSION != 2:
        send_msg(UDS()/UDS_NR(requestServiceId=0x11, negativeResponseCode=0x7F))

        return
    if pkt[UDS][UDS_ER].resetType != 0x01:
        send_msg(UDS()/UDS_NR(requestServiceId=0x11, negativeResponseCode=0x12))
        return
    
    gl.SEED = None
    gl.AUTH = False
    gl.SEND_ENOA = False
    gl.RETRIES = 0
    gl.TIME_ENOA_ACTIVATED = 0

    send_msg(UDS()/UDS_ERPR(resetType=0x01, powerDownTime=0x00))

def read_memory_by_address(pkt):
    from scapy.contrib.automotive.uds import UDS_RMBA, UDS_RMBAPR
    if gl.CURRENT_SESSION != 3:
        send_msg(UDS()/UDS_NR(requestServiceId=0x23, negativeResponseCode=0x7F))
        return
    
    memory_s = pkt[UDS][UDS_RMBA].memorySizeLen
    memory_a = pkt[UDS][UDS_RMBA].memoryAddressLen
    memory_size = 0
    memory_address = 0

    if memory_s == 1:
        memory_size = pkt[UDS][UDS_RMBA].memorySize1
    elif memory_s == 2:
        memory_size = pkt[UDS][UDS_RMBA].memorySize2
    elif memory_s == 3:
        memory_size = pkt[UDS][UDS_RMBA].memorySize3
    elif memory_s == 4:
        memory_size = pkt[UDS][UDS_RMBA].memorySize4

    if memory_a == 1:
        memory_address = pkt[UDS][UDS_RMBA].memoryAddress1
    elif memory_a == 2:
        memory_address = pkt[UDS][UDS_RMBA].memoryAddress2
    elif memory_a == 3:
        memory_address = pkt[UDS][UDS_RMBA].memoryAddress3
    elif memory_a == 4:
        memory_address = pkt[UDS][UDS_RMBA].memoryAddress4
    
    if memory_address > len(config.GENERATED_MEMORY) or memory_address + memory_size > len(config.GENERATED_MEMORY):
        send_msg(UDS()/UDS_NR(requestServiceId=0x23, negativeResponseCode=0x31))
        return
    
    gl.BUSY = True
    send_msg(UDS()/UDS_RMBAPR(dataRecord=b"".join(config.GENERATED_MEMORY[memory_address:memory_address+memory_size])))
    gl.BUSY = False

def write_data_by_identifier(pkt):
    from scapy.contrib.automotive.uds import UDS_WDBI, UDS_WDBIPR
    did = pkt[UDS][UDS_WDBI].dataIdentifier
    data = bytes(pkt[UDS][UDS_WDBI])[2:]

    if 0x2E not in config.DSC_SERVICES[gl.CURRENT_SESSION]:
        send_msg(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x7F))
        return

    if did not in config.DIDs_PER_SESSION[gl.CURRENT_SESSION]:
        send_msg(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x31))
        return

    if config.DATA_IDs[did][2] and not gl.AUTH:
        send_msg(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x33))
        return

    config.DATA_IDs[did] = (data, config.DATA_IDs[did][1],config.DATA_IDs[did][2])
    send_msg(UDS()/UDS_WDBIPR(dataIdentifier=did))
