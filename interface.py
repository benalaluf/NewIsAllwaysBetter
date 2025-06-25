
from scapy.all import conf, IFACES
from arp import *
from ethernet import *
from net import Net

class Interface:
    def __init__(self, iface):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface, promisc=True)
        self.mac = MacAddress(IFACES.dev_from_name(iface).mac)
        self.ip = IPAddress(IFACES.dev_from_name(iface).ip)

    def read_from_interface(self):
        return self.sock.recv_raw()[1] # raw bytes of packet
    
    def write_to_interface(self, data):
        pass
    
    def is_dst(self, ethernet):
        broadcast_mac = MacAddress("ff:ff:ff:ff:ff:ff")
        return ethernet.dst == self.mac or ethernet.dst == broadcast_mac

    def resolve(self, ip):
        arp = Arp(
            op=ArpOperationType.REQUEST,
            target_hw="ff:ff:ff:ff:ff:ff",
            sender_hw=self.mac,
            target_proto=ip,
            sender_proto=self.ip
            )
        
        eth = Ethernet(
            src=self.mac,
            dst="ff:ff:ff:ff:ff:ff",
            ethertype=EtherType.ARP,
            payload=bytes(arp),
            crc=
            )
        
        


    def handle(self):
        while True:
            data = self.read_from_interface()
            ethernet_layer = Ethernet(bytes=data)
            if self.is_dst(ethernet_layer):  
                match ethernet_layer.ethertype:
                    case EtherType.ARP:
                        Net().handle_arp(ethernet_layer.payload)
                    case _:
                        pass
