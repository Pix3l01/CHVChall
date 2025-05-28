import os

from pwnlib.adb import BootloaderImage

QUEUE_SIZE = 2

DSC_SESSIONS = {1, 2, 3}
SUPPORTED_SERVICES = {0x10, 0x11, 0x22, 0x23, 0x27, 0x3E}
DATA_ID = { 1:{1337:(b'Not here', False), 61840: (b'DRIVESEC_CA(R)N\'T', False),61842:(b'SW:1.3.3.7', False), 61844:(b'HW:over_9000', False)},
            2:{1337:(b'Not here', False), 31337:(os.getenv('FLAG', 'flag{tbd}').encode(), True), 32323:(b'Should put an easter egg...', True), 32324:(b'But am too lazy', True), 61842:(b'SW:0.0.0.1', False), 61844:(b'HW:0.0.-1', False)},
            3:{1337:(b'Not here', False), 61836: (b'2017MMDD',False),61842:(b'SW:1.3.3.7', False), 61844:(b'HW:over_9000', False)}}
MEMORY = {0: b'\x90'*256 + b'Is this a leak? Should we call a plumber? ', 2000: b'Drivesec'}
DSC_SERVICES = {1:{0x10, 0x22, 0x3E}, 2:{0x10, 0x11, 0x22, 0x23, 0x27, 0x3E}, 3:{0x10, 0x11, 0x22, 0x23, 0x27, 0x3E}}
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
    with open('/dev/random', 'rb') as f:
        leak = f.read(256)
    MEMORY[1337] = b'Did you forget the keys?' + leak
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


def key_check(key, access_level):
    # from global_stuff import SEED
    # from ctypes import CDLL
    # lib = CDLL("/chall/lib.so")
    # gen_key = lib.seed_key(SEED.seed)
    # if gen_key < 0:
    #     gen_key += 2**32
    # gen_key = gen_key.to_bytes(4, "big")
    #
    # return key == gen_key and access_level - 1 == SEED.level and SEED.is_valid()

    return True
