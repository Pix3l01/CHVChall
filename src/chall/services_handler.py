import time

from scapy.contrib.automotive.uds import UDS, UDS_NR
from scapy.packet import Raw

import config
import global_stuff as gl
from classes import SA_seed


def tester_present(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_TPPR
    gl.TIME_ELAPSED = 0
    sock.send(UDS()/UDS_TPPR()) 


def diagnostic_session_control(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_DSC, UDS_DSCPR

    new_session = pkt[UDS][UDS_DSC].diagnosticSessionType
    # If new session is the same as the current one do nothing, just reply with positive response
    if new_session == config.get_session():
        sock.send(UDS()/UDS_DSCPR(diagnosticSessionType=config.get_session()))
        return

    # Check whther the new session is accessible from the current one
    if new_session in config.ACCESSIBLE_SESSIONS[config.get_session()]:
        # Simulate bootloader switch when cheanging from/to session 2
        if new_session == 2 or config.get_session()== 2:
            gl.BUSY = True
            start = time.time()
            while time.time() - start < config.BOOTLOADER_SWITCH_TIMEOUT:
                sock.send(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x78))
                gl.TIME_ELAPSED = 0 
                time.sleep(1)
            gl.BUSY = False

        config.set_session(new_session)
        gl.AUTH = False
        sock.send(UDS()/UDS_DSCPR(diagnosticSessionType=config.get_session()))
    elif new_session in config.DSC_SESSIONS:
        # Session exists but is not accessible from the current one
        sock.send(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x22))
    else:
        # Session does not exist
        sock.send(UDS()/UDS_NR(requestServiceId=0x10, negativeResponseCode=0x12))


def read_data_by_identifier(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_RDBI, UDS_RDBIPR
    did = pkt[UDS][UDS_RDBI].identifiers[0]

    if did in config.DIDs_PER_SESSION[config.get_session()]:
        # If d_id can be read without auth
        session_did = config.DATA_IDs[did]
        if not session_did[1]:
            # session_did[did][0]
            sock.send(UDS()/UDS_RDBIPR(dataIdentifier=did)/Raw(session_did[0]))
            return
        elif session_did[1] and gl.AUTH:
            sock.send(UDS()/UDS_RDBIPR(dataIdentifier=did)/Raw(session_did[0]))
        else:
            sock.send(UDS()/UDS_NR(requestServiceId=0x22, negativeResponseCode=0x33))
    else:
        sock.send(UDS()/UDS_NR(requestServiceId=0x22, negativeResponseCode=0x31))


def security_access(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_SA, UDS_SAPR
    security_level = pkt[UDS][UDS_SA].securityAccessType

    if gl.SEND_ENOA:
        if time.time() - gl.TIME_ENOA_ACTIVATED > config.SEED_REQUEST_TIMEOUT:
            gl.SEND_ENOA = False
            gl.TIME_ENOA_ACTIVATED = 0
            gl.RETRIES = 0
        else:
            sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x36))    
            return

    if config.get_session(glob=False) not in config.SECURITY_ACCESS_LEVELS:
        sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x7F))
        return

    if security_level % 2 == 0:
        if security_level - 1 not in config.SECURITY_ACCESS_LEVELS[config.get_session(glob=False)]:
            sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x12))
            gl.SEED = None
            return
        
        if gl.SEED is None:
            sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x24))
            return
        
        if config.key_check(pkt[UDS][UDS_SA].securityKey, security_level):
            gl.RETRIES = 0
            gl.AUTH = True
            gl.SEED = None
            sock.send(UDS()/UDS_SAPR(securityAccessType=security_level))
        else:
            gl.SEED = None
            gl.RETRIES += 1
            if gl.RETRIES >= config.SEED_REQUEST_RETRIES:
                gl.SEND_ENOA = True
                gl.TIME_ENOA_ACTIVATED = time.time()
            sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x35))
    else:
        if security_level not in config.SECURITY_ACCESS_LEVELS[config.get_session(glob=False)]:
            sock.send(UDS()/UDS_NR(requestServiceId=0x27, negativeResponseCode=0x12))
            return
        if gl.SEED is None or not gl.SEED.is_valid() or gl.SEED.level != security_level:
            gl.SEED = SA_seed(security_level)
        sock.send(UDS()/UDS_SAPR(securityAccessType=security_level, securitySeed=gl.SEED.seed))


def ecu_reset(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_ER, UDS_ERPR
    if config.get_session() != 2:
        sock.send(UDS()/UDS_NR(requestServiceId=0x11, negativeResponseCode=0x7F))

        return
    if pkt[UDS][UDS_ER].resetType != 0x01:
        sock.send(UDS()/UDS_NR(requestServiceId=0x11, negativeResponseCode=0x12))
        return
    
    gl.SEED = None
    gl.AUTH = False
    gl.SEND_ENOA = False
    gl.RETRIES = 0
    gl.TIME_ENOA_ACTIVATED = 0

    sock.send(UDS()/UDS_ERPR(resetType=0x01, powerDownTime=0x00))


def read_memory_by_address(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_RMBA, UDS_RMBAPR
    if config.get_session() != 3:
        sock.send(UDS()/UDS_NR(requestServiceId=0x23, negativeResponseCode=0x7F))
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
        sock.send(UDS()/UDS_NR(requestServiceId=0x23, negativeResponseCode=0x31))
        return
    
    gl.BUSY = True
    sock.send(UDS()/UDS_RMBAPR(dataRecord=b"".join(config.GENERATED_MEMORY[memory_address:memory_address+memory_size])))
    gl.BUSY = False


def write_data_by_identifier(pkt, sock):
    from scapy.contrib.automotive.uds import UDS_WDBI, UDS_WDBIPR
    did = pkt[UDS][UDS_WDBI].dataIdentifier
    data = bytes(pkt[UDS][UDS_WDBI])[2:]

    if 0x2E not in config.DSC_SERVICES[config.get_session()]:
        sock.send(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x7F))
        return

    if did not in config.DIDs_PER_SESSION[config.get_session()] or did in config.UNWRITEABE_DIDs:  # don't want people to modify flag
        sock.send(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x31))
        return

    if config.DATA_IDs[did][2] and not gl.AUTH:
        sock.send(UDS()/UDS_NR(requestServiceId=0x2E, negativeResponseCode=0x33))
        return

    config.DATA_IDs[did] = (data, config.DATA_IDs[did][1],config.DATA_IDs[did][2])
    sock.send(UDS()/UDS_WDBIPR(dataIdentifier=did))
