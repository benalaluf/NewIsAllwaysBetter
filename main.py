from scapy.all import conf, IFACES
from ethernet import *
from arp import *
from interface import *
    
def main():
    iface = Interface("Ethernet")
    while True:
        data = iface.read_from_interface()
        ethernet_layer = Ethernet()
        if data[1]:
            ethernet_layer.parse_header(data[1])
            if ethernet_layer.ethertype == EtherType.ARP:
                print(ethernet_layer)
                arp = Arp()
                arp.parse_header(ethernet_layer.payload)
                print(iface.is_dst(ethernet_layer))
                print(arp)
                print("-"*20)

if __name__ == "__main__":
    main()