from scapy.contrib.automotive.uds import UDS, UDS_RMBA, UDS_DSC
from scapy.contrib.isotp import ISOTPNativeSocket


def read_by_address(sock: ISOTPNativeSocket):
    pkt = UDS() / UDS_RMBA(memoryAddressLen=3, memorySizeLen=3, memoryAddress3=0, memorySize3=2208)
    response = sock.sr1(pkt, verbose=0)
    with open("extracted", "wb") as f:
        f.write(response.dataRecord)


sock = ISOTPNativeSocket("vcan0", 2000, 1968, basecls=UDS, padding=True, fd=False)
sock.sr1(UDS() / UDS_DSC(diagnosticSessionType=3), verbose=0)
read_by_address(sock)