from interface import *
from ethernet import *
from arp import *
class Net:
    _instance = None

    def __init__(self):
        self.arp_table = ArpCache()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def handle_arp(self, data):
        arp = Arp()
        arp.parse_header(data)
        print(f"ARP op: {arp.operation}")
        if arp.operation == ArpOperationType.REPLY:
            print("-"*15)
            self.arp_table.updateTable(arp.sender_hw.addr, arp.sender_proto.addr)
            print(self.arp_table.table)

