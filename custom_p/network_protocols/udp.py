import struct
import extensions

from .dhcp import Dhcp


class Udp:
    name = 'udp'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, source_port, destination_port, length, checksum, payload=None):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['source_port',
                'destination_port',
                'length',
                'checksum',
                ]
        values = [self.source_port,
                  self.destination_port,
                  self.length,
                  self.checksum,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            pass
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

    def summary(self):
        return False

    @classmethod
    def from_raw(cls, data):
        # initialize
        source_port = None
        destination_port = None
        length = None
        checksum = None

        if len(data) < 8:
            return extensions.MalformedPacketException(f"UDP requires at least 8 bytes, got {len(data)}")
        
        # get values for fields the packet has
        source_port, destination_port, length, checksum = struct.unpack('!HHHH', data[:8])

        # save payload
        # if we know the next proto, parse the payload
        data = data[:length]
        payload = data[8:]
        if destination_port == 67 or destination_port == 68:
            payload = Dhcp.from_raw(payload)

        return cls(source_port, destination_port, length, checksum, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        source_port = cond.get('source_port')
        destination_port = cond.get('destination_port')
        length = cond.get('length')
        checksum = cond.get('checksum')

        return cls(source_port, destination_port, length, checksum)

