
from scapy.all import conf, IFACES
from ethernet import *

class Interface:
    def __init__(self, iface):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface, promisc=True)
        self.mac = mac_from_addr(IFACES.dev_from_name(iface).mac)

    def read_from_interface(self):
        return self.sock.recv_raw()[1] # raw bytes of packet
    
    def write_to_interface(self, data):
        self.sock.send(data)
        
    def is_dst(self, ethernet):
        broadcast_mac = mac_from_addr("ff:ff:ff:ff:ff:ff")
        return ethernet.dst == self.mac or ethernet.dst == broadcast_mac


    def handle(self):
        while True:
            data = self.read_from_interface()
            if data:
                ethernet_layer = Ethernet(bytes=data)
                match ethernet_layer.ethertype:
                    case EtherType.IP_V4:
                        print(ethernet_layer)
                        print("-"*20)
                    case EtherType.ARP:
                        print(ethernet_layer)
                        print("-"*20)
                    case _:
                        pass


