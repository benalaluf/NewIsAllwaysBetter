from dataclasses import dataclass, field
from ip import IPAddress
from ethernet import *
from enum import Enum

ARP_HW_TYPE_SIZE = 2
ARP_PROTO_TYPE_SIZE = 2
ARP_HW_LEN_SIZE = 1
ARP_PROTO_LEN_SIZE = 1
ARP_OP_SIZE = 2


class ArpOperationType(Enum):
    REQUEST = b'\x00\x01'
    REPLY = b'\x00\x02'
    UNKNOWN = b'\xFF\xFF'

class Arp:

    def __init__(self, bytes =None, hw_type=b'\x00\01', proto_type=b'\x08\x00', hw_len=6 ,proto_len=4,op=None,
                 sender_hw=None, sender_proto=None, target_hw=None, target_proto=None):

        self.hardware_type = hw_type
        self.protocol_type = proto_type
        self.hw_len = hw_len
        self.proto_len = proto_len
        self.operation = op
        self.sender_hw = MacAddress(addr=sender_hw)
        self.sender_proto = IPAddress(addr=sender_proto)
        self.target_hw = MacAddress(addr=target_hw)
        self.target_proto = IPAddress(addr=target_proto)
        
        if bytes:
            self.from_bytes(bytes)

    def __bytes__(self):
        raw_data = b''
        raw_data += self.hardware_type
        raw_data += self.protocol_type
        raw_data += struct.pack("<B", self.hw_len)
        raw_data += struct.pack("<B", self.proto_len)
        raw_data += self.operation.value 
        raw_data += bytes(self.sender_hw)
        raw_data += bytes(self.sender_proto)
        raw_data += bytes(self.target_hw)
        raw_data += bytes(self.target_proto)

        return raw_data

    def from_bytes(self, data):
        data_parser = parse_bytes(data)
        next(data_parser)
        self.hardware_type = data_parser.send(ARP_HW_TYPE_SIZE) 
        self.protocol_type =  data_parser.send(ARP_PROTO_TYPE_SIZE) 
        self.hw_len = struct.unpack("<b" ,data_parser.send(ARP_HW_LEN_SIZE))[0]
        self.proto_len = struct.unpack("<b", data_parser.send(ARP_PROTO_LEN_SIZE))[0]
        
        try:
            self.operation = ArpOperationType(data_parser.send(ARP_OP_SIZE))
        except ValueError:
            self.operation = ArpOperationType.UNKNOWN

        if self.protocol_type == b'\x08\x00' and self.hardware_type == b'\x00\x01':
            self.sender_hw.from_bytes(data_parser.send(self.hw_len))
            self.sender_proto.from_bytes(data_parser.send(self.proto_len))
            self.target_hw.from_bytes(data_parser.send(self.hw_len))
            self.target_proto.from_bytes(data_parser.send(self.proto_len))

        else:
            raise ValueError("Unkown proto/hw types")

class ArpCache:
    def __init__(self):
        self.table = dict()

    def getIP(self, hw):
        return self.table.get(hw)
    
    def updateTable(self, hw, ip):
        self.table[hw] = ip
