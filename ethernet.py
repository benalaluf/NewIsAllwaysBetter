from dataclasses import dataclass
import struct


@dataclass
class Ethernet:
    dst: bytes = None
    src: bytes = None
    ethertype: bytes = None
    payload: bytes = None
    crc: bytes = None

    def parse_header(self, data):
        self.dst = data[:6]
        self.src = data[6:13]
        self.ethertype = data[13:15]
        self.payload = data[15:-4]
        self.crc = data[-4:]
    
    def __repr__(self):
        data_str = f"dst: {self.dst}\nsrc: {self.src}\ntype: {self.ethertype}\npayload: {self.payload}\ncrc: {self.crc}"
        return data_str


