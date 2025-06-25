from scapy.all import conf, IFACES
from ethernet import *
from arp import *
from interface import *
import struct
def main():
    iface = Interface("Ethernet")
    iface.handle()
   

if __name__ == "__main__":
    main()