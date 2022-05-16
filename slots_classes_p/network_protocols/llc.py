import struct
import extensions

from .ipv4 import Ipv4
from .arp import Arp
from .dot1x_authentication import Dot1xAuthentication


class Llc:
    __slots__ = 'dsap', 'ssap', 'control_field', 'organization_code', 'type', 'payload'
    name = 'llc'

    def __init__(self, dsap, ssap, control_field, organization_code, type, payload=None):
        self.dsap = dsap
        self.ssap = ssap
        self.control_field = control_field
        self.organization_code = organization_code
        self.type = type
        
        self.payload = payload

    def summary(self):
        return False

    @classmethod
    def from_raw(cls, data):
        if len(data) < 8:
            return extensions.MalformedPacketException(f"LLC requires at least 3 bytes, got {len(data)}")

        organization_code = None
        type = None
        payload = None

        dsap, ssap, control_field = struct.unpack('!BBB', data[:3])

        if dsap in (0xaa, 0xab):
            organization_code, type = struct.unpack('!3sH', data[3:8])

            data = data[8:]
            payload = None
            if type == 0x0800:
                payload = Ipv4.from_raw(data)
            elif type == 0x0806:
                payload = Arp.from_raw(data)
            elif type == 0x888e:
                payload = Dot1xAuthentication.from_raw(data)

        return cls(dsap, ssap, control_field, organization_code, type, payload)
