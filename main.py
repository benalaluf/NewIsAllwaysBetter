from scapy.all import conf, IFACES
from ethernet import *


def read_from_interface(iface):
    sock = conf.L2socket(iface=iface, promisc=True) # Create the socket
    return sock.recv_raw() # Receive data



if __name__ == "__main__":
    data = read_from_interface("Ethernet")
    ethernet_layer = Ethernet()
    ethernet_layer.parse_header(data[1])
    print(ethernet_layer)
