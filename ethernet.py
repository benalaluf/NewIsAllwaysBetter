from dataclasses import dataclass, field
from enum import Enum
import struct
from utils import parse_bytes

MAC_ADDRESS_SIZE = 6
ETHER_TYPE_SIZE = 2
CRC_SIZE = 4

PACK_CRC = "<I"
PACK_ETHER_TYPE = "<H"

class EtherType(Enum):
    IP_V4 = b'\x08\x00'
    ARP = b'\x08\x06'
    UNKNOWN = b'\xFF\xFF'

@dataclass 
class MacAddress:
    addr: str = None

    def __bytes__(self):
        mac = self.addr.replace(":", '')
        return bytes.fromhex(mac)

    def from_bytes(self, bytes):
       self.addr = bytes.hex(sep=":") 


class Ethernet:

    def __init__(self, bytes = None, dst=None, src=None,ethertype=None, payload: bytes=None, crc=None):
        self.dst = MacAddress(addr=dst)
        self.src = MacAddress(addr=src)
        self.ethertype = ethertype
        self.payload = payload
        self.crc = crc

        if bytes:
            self.from_bytes(bytes)
        

    def __bytes__(self):
        raw_data = b''
        raw_data += bytes(self.dst)
        raw_data += bytes(self.src)
        raw_data += struct.pack(PACK_ETHER_TYPE, self.ethertype)
        raw_data += self.payload
        raw_data += struct.pack(PACK_CRC, self.crc)

        return raw_data

    def from_bytes(self, data: bytes):

        data_parser = parse_bytes(data)
        next(data_parser)

        self.dst.from_bytes(data_parser.send(MAC_ADDRESS_SIZE))
        self.src.from_bytes(data_parser.send(MAC_ADDRESS_SIZE))
        
        try:
            self.ethertype = EtherType(data_parser.send(ETHER_TYPE_SIZE))
        except ValueError:
            self.ethertype = EtherType.UNKNOWN

        self.payload = data_parser.send(-CRC_SIZE)
        self.crc = data[-CRC_SIZE:]
    
    def __repr__(self):
        data_str = f"dst: {self.dst}\nsrc: {self.src}\ntype: {self.ethertype}\npayload: {self.payload}\ncrc: {self.crc}"
        return data_str


