import os

QUEUE_SIZE = 2

DSC_SESSIONS = {1, 2, 3}
SUPPORTED_SERVICES = {0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}
# format: id (int) -> tuple(content (bytes), is SA needed to read (bool), is SA needed to modify (bool))
DATA_IDs = {
    1337:(b'Not here', False, True), 
    31337:(os.getenv('FLAG', 'flag{tbd}').encode(), True, True), 
    61746: (b'\x01',False, False), 
    61808:(b'Why do pistons make such bad employees? ', False, True),
    61809:(b'They only work after they are fired', False, True),
    61810:(b'My wife gave birth to our son in the car on our way to the hospital.', False, True),
    61811:(b'We named him Carson.', False, True),
    61812:(b'What\'s the best pickup line?', False, True),
    61813:(b'Wanna hang out in my bed?', False, True),
    61814:(b'How did the hacker get away from the FBI? ', False, True),
    61815:(b'He ransomware ', False, True),
    61816:(b'When I die I want to go peacefully in my sleep like my grandfather.', False, True),
    61817:(b'Not screaming and crying like the passengers in the car he was driving', False, True),
    61818:(b'Why did the chicken cross the road?', False, True),
    61819:(b'To prove to the possum it could be done.', False, True),
    61820:(b'What kind of car does a sheep drive?', False, True),
    61821:(b'A Lamb-orghini.', False, True),
    61822:(b'What happens when you leave your ADHD medication in your Ford Fiesta?', False, True),
    61823:(b'It turns into a Ford Focus.', False, True),
    61824:(b'Sorry not sorry for the bad jokes', False, True),
    61840: (b'DRIVESEC_CA(R)N\'T', False, False),
    61842:(b'SW:0.0.0.1', False, True), 
    61844:(b'HW:0.0.-1', False, True)
    }
DIDs_PER_SESSION = {
    1: [1337, 61746, 61808, 61809, 61810, 61811, 61812, 61813, 61814, 61815, 61816, 61817, 61818, 61819, 61820, 61821, 61822, 61823, 61824, 61840, 61842, 61844], 
    2: [1337, 31337, 61746,61808, 61809, 61810, 61811, 61812, 61813, 61814, 61815, 61816, 61817, 61818, 61819, 61820, 61821, 61822, 61823, 61824, 61842, 61844], 
    3: [1337, 61746, 61808, 61809, 61810, 61811, 61812, 61813, 61814, 61815, 61816, 61817, 61818, 61819, 61820, 61821, 61822, 61823, 61824, 61836, 61842, 61844]
    }
UNWRITEABE_DIDs = [31337]
MEMORY = {0: b'\x90'*256 + b'Is this a leak? Should we call a plumber? ', 2200: b'Drivesec'}
DSC_SERVICES = {1:{0x10, 0x22, 0x3E}, 2:{0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}, 3:{0x10, 0x11, 0x22, 0x23, 0x27, 0x2E, 0x3E}}
ACCESSIBLE_SESSIONS = {1: [3], 2: [3], 3: [1, 2]}
SECURITY_ACCESS_LEVELS = {2: [9], 3: [1,3]}
DEFAULT_SESSION = 1
SESSION_RESET_TIMEOUT = 2
BOOTLOADER_SWITCH_TIMEOUT = 3
SEED_REQUEST_TIMEOUT = 60*3
SEED_REQUEST_RETRIES = 3
IFACE = os.getenv('IFACE')
if not IFACE:
    raise ValueError("Environment variable 'IFACE' must be set to the network interface name.")
TX_ID = 0x742
RX_ID = 0x769

GENERATED_MEMORY = []

def generate_memory():
    global GENERATED_MEMORY
    global MEMORY
    leak = b''
    with open('./leak.bin', 'rb') as f:
        leak = f.read()
    MEMORY[1337] = b'Did you lock yourself out without the keys?\x00' + leak + b'\x00\x00\x00x86:LE:64:gcc'

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


def get_session(to_bytes: bool = False, glob: bool = True) -> int|bytes:
    if glob:
        import global_stuff as gl
        session = gl.CURRENT_SESSION.to_bytes(1, 'big')
    else:
        session = DATA_IDs[61746][0]
    if to_bytes:
        return session
    else:
        return int.from_bytes(session, 'big')


def set_session(session: bytes | int, glob: bool = True) -> None:
    if isinstance(session, int):
        session = int.to_bytes(session, 1, 'big')

    if glob:
        import global_stuff as gl
        gl.CURRENT_SESSION = int.from_bytes(session, byteorder='big')
    DATA_IDs[61746] = (session, False, False)


def key_check(key, access_level):
    from global_stuff import SEED
    from ctypes import CDLL, c_uint64
    if SEED is None:
        return False
    lib = CDLL("./lib.so")
    lib.programming.restype = c_uint64
    lib.extended.restype = c_uint64
    if get_session(glob=False) == 2:
        gen_key = lib.programming(SEED.seed)
    elif get_session(glob=False) == 3:
        gen_key = lib.extended(SEED.seed)
    else:
        return False

    gen_key = gen_key.to_bytes(8, "big")
    return key == gen_key and access_level - 1 == SEED.level and SEED.is_valid()
    #return True
