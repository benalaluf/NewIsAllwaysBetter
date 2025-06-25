from scapy.all import conf, IFACES
from interface import Interface
from ethernet import *
from interface import *
import struct

def main():
    IFACES.show()
    index = input("Enter index:")
    inter = IFACES.dev_from_index(index)
    iface = Interface(inter.name)
    iface.handle()
   

if __name__ == "__main__":
    main()
    
    
    