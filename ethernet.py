from dataclasses import dataclass, field
from enum import Enum
import struct

class EtherType(Enum):
    IP_V4 = b'\x00E'
    UNKNOWN = b'\xFF\xFF'

@dataclass 
class MacAddress:
    addr: str = None

    def __bytes__(self):
        mac = self.addr.replace(":", '')
        return bytes.fromhex(mac)

    def from_bytes(self, bytes):
       self.addr = bytes.hex(sep=":") 


@dataclass
class Ethernet:
    dst: MacAddress   = field(default_factory=MacAddress)
    src: MacAddress   = field(default_factory=MacAddress)
    ethertype: EtherType = None 
    payload: bytes = None
    crc: bytes = None

    def parse_header(self, data):
        self.dst.from_bytes(data[:6])
        self.src.from_bytes(data[6:13])
        
        try:
            self.ethertype = EtherType(data[13:15])
        except ValueError:
            self.ethertype = EtherType.UNKNOWN

        self.payload = data[15:-4]
        self.crc = data[-4:]
    
    def __repr__(self):
        data_str = f"dst: {self.dst}\nsrc: {self.src}\ntype: {self.ethertype}\npayload: {self.payload}\ncrc: {self.crc}"
        return data_str


