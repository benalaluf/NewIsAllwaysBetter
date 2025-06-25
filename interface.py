
from scapy.all import conf, IFACES
from ethernet import *

class Interface:
    def __init__(self, iface):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface, promisc=True)
        self.mac = MacAddress(IFACES.dev_from_name(iface).mac)


    def read_from_interface(self):
        return self.sock.recv_raw()
    
    
    def is_dst(self, ethernet):
        broadcast_mac = MacAddress("ff:ff:ff:ff:ff:ff")
        return ethernet.dst == self.mac  or ethernet.dst == broadcast_mac