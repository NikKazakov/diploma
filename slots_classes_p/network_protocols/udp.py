import struct
import extensions

from .dhcp import Dhcp


class Udp:
    __slots__ = 'source_port', 'destination_port', 'length', 'checksum', 'payload'
    name = 'udp'

    def __init__(self, source_port, destination_port, length, checksum, payload=None):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum
        
        self.payload = payload

    def summary(self):
        return False

    @classmethod
    def from_raw(cls, data):
        if len(data) < 8:
            return extensions.MalformedPacketException(f"UDP requires at least 8 bytes, got {len(data)}")
        
        source_port, destination_port, length, checksum = struct.unpack('!HHHH', data[:8])

        data = data[:length]
        payload = data[8:]
        if destination_port == 67 or destination_port == 68:
            payload = Dhcp.from_raw(payload)

        return cls(source_port, destination_port, length, checksum, payload)
