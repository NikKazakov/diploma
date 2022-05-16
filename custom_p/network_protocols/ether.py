import struct
import extensions

from .arp import Arp
from .ipv4 import Ipv4


class Ether:
    name = 'ether'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, destination, source, length, payload=None):
        self.destination = destination
        self.source = source
        self.length = length
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['destination',
                'source',
                'length',
                ]
        values = [self.destination,
                  self.source,
                  self.length,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'destination' in ret:
                ret['destination'] = extensions.int_to_mac(ret['destination'])
            if 'source' in ret:
                ret['source'] = extensions.int_to_mac(ret['source'])
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

    def get_src(self):
        return extensions.int_to_mac(self.source)

    def get_dst(self):
        return extensions.int_to_mac(self.destination)

    def summary(self):
        return f'Ether {self.get_src()} -> {self.get_dst()}'

    @classmethod
    def from_raw(cls, data):
        # initialize
        destination = None
        source = None
        length = None

        if len(data) < 14:
            return extensions.MalformedPacketException(f"Ethernet requires at least 14 bytes, got {len(data)}")
        
        # get values for fields the packet has
        destination, source, length = struct.unpack('!6s6sH', data[:14])
        destination = int.from_bytes(destination, 'big')
        source = int.from_bytes(source, 'big')

        # save payload
        # if we know the next proto, parse the payload
        payload = data[14:]
        if length == 2048:
            payload = Ipv4.from_raw(payload)
        elif length == 0x806:
            payload = Arp.from_raw(payload)

        return cls(destination, source, length, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        destination = cond.get('destination')
        source = cond.get('source')
        length = cond.get('length')

        return cls(destination, source, length)

