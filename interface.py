
from scapy.all import conf, IFACES
from arp import Arp
from ethernet import *
from net import Net

class Interface:
    def __init__(self, iface):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface, promisc=True)
        self.mac = MacAddress(IFACES.dev_from_name(iface).mac)

    def read_from_interface(self):
        return self.sock.recv_raw()[1] # raw bytes of packet
        
    def is_dst(self, ethernet):
        broadcast_mac = MacAddress("ff:ff:ff:ff:ff:ff")
        return ethernet.dst == self.mac or ethernet.dst == broadcast_mac
    
    def handle(self):
        while True:
            data = self.read_from_interface()
            ethernet_layer = Ethernet(bytes=data)
            
            match ethernet_layer.ethertype:
                case EtherType.ARP:
                    Net().handle_arp(ethernet_layer.payload)
                case _:
                    pass
