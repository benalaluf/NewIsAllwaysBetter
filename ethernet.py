from ctypes import Structure, c_byte, c_ushort, c_wchar
from dataclasses import dataclass, field
from enum import Enum
import struct

MAC_ADDRESS_SIZE = 6
ETHER_TYPE_SIZE = 2
CRC_SIZE = 4
HEADER_SIZE = MAC_ADDRESS_SIZE * 2 + ETHER_TYPE_SIZE

PACK_CRC = "<I"
PACK_ETHER_TYPE = "<H"

class EtherType:
    IP_V4 = 0x0008 
    ARP = 0x0608
    UNKNOWN = 0xFFFF

class MacAddress(Structure):
    
    _fields_ = [
        ("addr", c_byte * 6)
    ]


def mac_from_addr(string):
    addr = bytes.fromhex(string.replace(":", ""))
    return MacAddress.from_buffer_copy(addr)

def mac_to_str(mac):
    return bytes(mac).hex(":")


class EthernetHeader(Structure):
    _fields_ = [
            ('src', MacAddress),
            ('dst', MacAddress),
            ('ethertype', c_ushort),
        ]

class Ethernet:

    def __init__(self, bytes = None, header: EthernetHeader = None, payload: bytes=None, crc=None):
        if bytes:
            self.from_bytes(bytes)
        else:
            self.header = header
            self.src = header.src
            self.dst = header.dst
            self.ethertype = header.ethertype
            self.payload = payload
            self.crc = crc

        
    def __bytes__(self):
        raw_data = b''
        raw_data += bytes(self.header)
        raw_data += self.payload
        raw_data += struct.pack(PACK_CRC, self.crc)

        return raw_data

    def from_bytes(self, data: bytes):
        self.header = EthernetHeader.from_buffer_copy(data)
        self.src = self.header.src
        self.dst = self.header.dst
        self.ethertype = self.header.ethertype
        self.payload = data[HEADER_SIZE:-CRC_SIZE]
        self.crc = data[-CRC_SIZE:]
    
    def __repr__(self):
        data_str = f"dst: {mac_to_str(self.dst)}\nsrc: {mac_to_str(self.src)}\ntype: {self.ethertype}\npayload: {self.payload}\ncrc: {self.crc}"
        return data_str


