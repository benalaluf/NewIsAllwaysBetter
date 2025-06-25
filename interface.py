
from scapy.all import conf, IFACES
from arp import *
from ethernet import *
from net import Net
from binascii import crc32
class Interface:
    def __init__(self, iface):
        self.iface = iface
        self.sock = conf.L2socket(iface=iface, promisc=True)
        self.mac = MacAddress(IFACES.dev_from_name(iface).mac)
        self.ip = IPAddress(IFACES.dev_from_name(iface).ip)

    def read_from_interface(self):
        return self.sock.recv_raw()[1] # raw bytes of packet
    
    def write_to_interface(self, data):
        self.sock.send(data)
        
    def is_dst(self, ethernet):
        broadcast_mac = MacAddress("ff:ff:ff:ff:ff:ff")
        return ethernet.dst == self.mac or ethernet.dst == broadcast_mac

    def resolve(self, ip):
        arp = Arp(
            op=ArpOperationType.REQUEST,
            target_hw="ff:ff:ff:ff:ff:ff",
            sender_hw=self.mac.addr,
            target_proto=ip,
            sender_proto=self.ip.addr
            )
        
        eth = Ethernet(
            src=self.mac.addr,
            dst="ff:ff:ff:ff:ff:ff",
            ethertype=EtherType.ARP,
            payload=bytes(arp),
            crc=crc32(bytes(arp))
            )
        
        self.write_to_interface(bytes(eth))
        
        


    def handle(self):
        self.resolve("192.168.68.69")
        while True:
            data = self.read_from_interface()
            ethernet_layer = Ethernet(bytes=data)
            if self.is_dst(ethernet_layer):  
                match ethernet_layer.ethertype:
                    case EtherType.ARP:
                        Net().handle_arp(ethernet_layer.payload)
                    case _:
                        pass
