import struct
import extensions

from .ipv4 import Ipv4
from .arp import Arp
from .dot1x_authentication import Dot1xAuthentication


class Llc:
    name = 'llc'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, dsap, ssap, control_field, organization_code, type, payload=None):
        self.dsap = dsap
        self.ssap = ssap
        self.control_field = control_field
        self.organization_code = organization_code
        self.type = type
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['dsap',
                'ssap',
                'control_field',
                'organization_code',
                'type',
                ]
        values = [self.dsap,
                  self.ssap,
                  self.control_field,
                  self.organization_code,
                  self.type,
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
        dsap = None
        ssap = None
        control_field = None
        organization_code = None
        type = None

        if len(data) < 8:
            return extensions.MalformedPacketException(f"LLC requires at least 8 bytes, got {len(data)}")
        
        # get values for fields the packet has
        dsap, ssap, control_field, organization_code, type = struct.unpack('!BBB3sH', data[:8])

        # save payload
        # if we know the next proto, parse the payload
        data = data[8:]
        payload = None
        if type == 0x0800:
            payload = Ipv4.from_raw(data)
        elif type == 0x0806:
            payload = Arp.from_raw(data)
        elif type == 0x888e:
            payload = Dot1xAuthentication.from_raw(data)

        return cls(dsap, ssap, control_field, organization_code, type, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        dsap = cond.get('dsap')
        ssap = cond.get('ssap')
        control_field = cond.get('control_field')
        organization_code = cond.get('organization_code')
        type = cond.get('type')

        return cls(dsap, ssap, control_field, organization_code, type)

