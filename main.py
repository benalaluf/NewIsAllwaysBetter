from scapy.all import conf, IFACES
from ethernet import *

def read_from_interface(iface):
    sock = conf.L2socket(iface=iface, promisc=True)
    return sock.recv_raw()

def is_dst(iface, ethernet):
    iface_mac = MacAddress(IFACES.dev_from_name(iface).mac)
    broadcast_mac = MacAddress("ff:ff:ff:ff:ff:ff")
    return ethernet.dst == iface_mac  or ethernet.dst == broadcast_mac
    

if __name__ == "__main__":
    iface = "Ethernet"
    #Todo: classify
    while True:
        data = read_from_interface(iface)
        ethernet_layer = Ethernet()
        # print(data[1])
        if data[1]:
            ethernet_layer.parse_header(data[1])
            if ethernet_layer.ethertype == EtherType.ARP:
                print(ethernet_layer)
                print(is_dst(iface, ethernet_layer))
                print("-"*20)
