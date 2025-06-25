from dataclasses import dataclass, field
import struct

@dataclass 
class IPAddress:
    addr: str = None

    def __bytes__(self):
        addr_bytes = b'' 
        for p in self.addr.split("."):
            addr_bytes+= struct.pack("<B", int(p))
        
        return addr_bytes 

    def from_bytes(self, bytes):
        addr = ""
        for byte in bytes:
            addr+= str(byte) + "."
        self.addr = addr[:-1]

             