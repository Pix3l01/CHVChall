import os

QUEUE_SIZE = 2

DSC_SESSIONS = {1, 2, 3}
SUPPORTED_SERVICES = {0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}
DATA_IDs = {1337:(b'Not here', False, True), 31337:(os.getenv('FLAG', 'flag{tbd}').encode(), True, True), 61746: (b'\x01',False, False), 61840: (b'DRIVESEC_CA(R)N\'T', False, False),61842:(b'SW:0.0.0.1', False, True), 61844:(b'HW:0.0.-1', False, True)}
DIDs_PER_SESSION = {1: [1337, 61746, 61840, 61842, 61844], 2: [1337, 31337, 61746, 61842, 61844], 3: [1337, 61746, 61836, 61842, 61844]}
MEMORY = {0: b'\x90'*256 + b'Is this a leak? Should we call a plumber? ', 2200: b'Drivesec'}
DSC_SERVICES = {1:{0x10, 0x22, 0x3E}, 2:{0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}, 3:{0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}}
ACCESSIBLE_SESSIONS = {1: [3], 2: [3], 3: [1, 2]}
SECURITY_ACCESS_LEVELS = {2: [9], 3: [1,3]}
DEFAULT_SESSION = 1
SESSION_RESET_TIMEOUT = 2
BOOTLOADER_SWITCH_TIMEOUT = 7
SEED_REQUEST_TIMEOUT = 7
SEED_REQUEST_RETRIES = 3
IFACE = 'vcan0'
TX_ID = 0x7B0
RX_ID = 0x7D0

GENERATED_MEMORY = []

def generate_memory():
    global GENERATED_MEMORY
    global MEMORY
    leak = b''
    with open('./leak.bin', 'rb') as f:
        leak = f.read()
    MEMORY[1337] = b'Did you forget the keys?' + leak + b'\x00\x00\x00x86:LE:64:gcc'

    i = 0
    ma = max(MEMORY)
    total = ma + len(MEMORY[ma])
    while i < total:
        if i in MEMORY:
            for ii in range(len(MEMORY[i])):
                GENERATED_MEMORY.append(MEMORY[i][ii].to_bytes(1, 'big'))
            i += len(MEMORY[i])
        else:
            GENERATED_MEMORY.append(b'\x00')
            i += 1


def get_session(to_bytes: bool = False) -> int|bytes:
    if to_bytes:
        return DATA_IDs[61746][0]
    else:
        return int.from_bytes(DATA_IDs[61746][0], 'big')


def set_session(session: bytes | int) -> None:
    if isinstance(session, int):
        session = int.to_bytes(session, 1, 'big')
    DATA_IDs[61746] = (session, False, False)


def key_check(key, access_level):
    from global_stuff import SEED
    from ctypes import CDLL, c_uint64
    lib = CDLL("./lib.so")
    lib.programming.restype = c_uint64
    lib.extended.restype = c_uint64
    if get_session() == 2:
        gen_key = lib.programming(SEED.seed)
    elif get_session() == 3:
        gen_key = lib.extended(SEED.seed)
    else:
        return False

    gen_key = gen_key.to_bytes(8, "big")
    return key == gen_key and access_level - 1 == SEED.level and SEED.is_valid()
    #return True
