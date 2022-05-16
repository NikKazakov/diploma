import struct
import extensions

from .arp import Arp
from .ipv4 import Ipv4


class Ether:
    __slots__ = 'destination', 'source', 'length', 'payload'
    name = 'ether'

    def __init__(self, destination, source, length, payload=None):
        self.destination = destination
        self.source = source
        self.length = length
        
        self.payload = payload

    def summary(self):
        return f"Ether {extensions.get_bytes_to_mac(self.source)} -> {extensions.get_bytes_to_mac(self.destination)}"

    @classmethod
    def from_raw(cls, data):
        if len(data) < 14:
            return extensions.MalformedPacketException(f"Ethernet requires at least 14 bytes, got {len(data)}")
        
        destination, source, length = struct.unpack('!6s6sH', data[:14])
        destination = int.from_bytes(destination, 'big')
        source = int.from_bytes(source, 'big')

        payload = data[14:]
        if length == 2048:
            payload = Ipv4.from_raw(payload)
        elif length == 0x806:
            payload = Arp.from_raw(payload)

        return cls(destination, source, length, payload)
