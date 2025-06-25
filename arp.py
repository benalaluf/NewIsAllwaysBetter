from dataclasses import dataclass, field
from ip import IPAddress
from ethernet import *
from enum import Enum

class ArpOperationType(Enum):
    REQUEST = b'\x00\x01'
    REPLY = b'\x00\x02'
    UNKNOWN = b'\xFF\xFF'

@dataclass
class Arp:
    hardware_type: bytes = None
    protocol_type: bytes = None
    hw_len: bytes  = None
    proto_len: bytes  = None
    operation: ArpOperationType  = None
    sender_hw: MacAddress = field(default_factory=MacAddress)
    sender_proto: IPAddress = field(default_factory=IPAddress)
    target_hw: MacAddress = field(default_factory=MacAddress)
    target_proto: IPAddress = field(default_factory=IPAddress)

    def parse_header(self, data):
        self.hardware_type = data[:2]
        self.protocol_type = data[2:4]
        self.hw_len = data[4]
        self.proto_len = data[5]
        try:
            self.operation = ArpOperationType(data[6:8])
        except ValueError:
            self.operation = ArpOperationType.UNKNOWN

        offset = 8

        if self.protocol_type == b'\x08\x00' and self.hardware_type == b'\x00\x01':
            self.sender_hw.from_bytes(data[offset: offset + self.hw_len])
            offset += self.hw_len
            self.sender_proto.from_bytes(data[offset: offset + self.proto_len])
            offset += self.proto_len
            self.target_hw.from_bytes(data[offset: offset+ self.hw_len])
            offset += self.hw_len
            self.target_proto.from_bytes(data[offset: offset+self.proto_len])

        else:
            raise ValueError("Unkown proto/hw types")

class ArpCache:
    def __init__(self):
        self.table = dict()

    def getIP(self, hw):
        return self.table.get(hw)
    
    def updateTable(self, hw, ip):
        self.table[hw] = ip
