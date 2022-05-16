import struct
import extensions

from .udp import Udp


class Ipv4:
    name = 'ipv4'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, source, destination, options, payload=None):
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecn = ecn
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source = source
        self.destination = destination
        self.options = options
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['version',
                'ihl',
                'dscp',
                'ecn',
                'total_length',
                'identification',
                'flags',
                'fragment_offset',
                'ttl',
                'protocol',
                'header_checksum',
                'source',
                'destination',
                'options',
                ]
        values = [self.version,
                  self.ihl,
                  self.dscp,
                  self.ecn,
                  self.total_length,
                  self.identification,
                  self.flags,
                  self.fragment_offset,
                  self.ttl,
                  self.protocol,
                  self.header_checksum,
                  self.source,
                  self.destination,
                  self.options,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'source' in ret:
                ret['source'] = extensions.int_to_ipv4(ret['source'])
            if 'destination' in ret:
                ret['destination'] = extensions.int_to_ipv4(ret['destination'])
            pass
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

    def get_src(self):
        return extensions.int_to_ipv4(self.source)

    def get_dst(self):
        return extensions.int_to_ipv4(self.destination)

    def summary(self):
        return f'{self.get_src()} -> {self.get_dst()}'

    @classmethod
    def from_raw(cls, data):
        # initialize
        version = None
        ihl = None
        dscp = None
        ecn = None
        total_length = None
        identification = None
        flags = None
        fragment_offset = None
        ttl = None
        protocol = None
        header_checksum = None
        source = None
        destination = None
        options = None

        if len(data) < 20:
            return extensions.MalformedPacketException(f'IPv4 requires at least 20 bytes, got {len(data)}')

        # get values for fields the packet has
        vide, total_length, identification, flags_fr_offset, ttl, protocol, header_checksum, source, destination \
            = struct.unpack('!2sHH2sBBH4s4s', data[:20])

        version = vide[0] >> 4
        ihl = vide[0] & 15
        dscp = vide[1] >> 6
        ecn = vide[1] & 3
        flags = flags_fr_offset[0] >> 5
        flags_fr_offset = bytearray(flags_fr_offset)
        flags_fr_offset[0] = flags_fr_offset[0] & 31
        fragment_offset = int.from_bytes(flags_fr_offset, 'big')
        source = int.from_bytes(source, 'big')
        destination = int.from_bytes(destination, 'big')
        options = None

        if ihl > 5:
            options_length = (ihl - 5) * 4
            try:
                options = struct.unpack(f'{options_length}s', data[20:20+options_length])
            except struct.error as e:
                print(f"DEBUG got options of incorrect size: {e}")
                options = struct.unpack(f'{len(data)-20}s', data[20:])

        # save payload
        # if we know the next proto, parse the payload
        payload = data[ihl*4:]
        if protocol == 17:
            payload = Udp.from_raw(payload)

        return cls(version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, source, destination, options, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        version = cond.get('version')
        ihl = cond.get('ihl')
        dscp = cond.get('dscp')
        ecn = cond.get('ecn')
        total_length = cond.get('total_length')
        identification = cond.get('identification')
        flags = cond.get('flags')
        fragment_offset = cond.get('fragment_offset')
        ttl = cond.get('ttl')
        protocol = cond.get('protocol')
        header_checksum = cond.get('header_checksum')
        source = cond.get('source')
        destination = cond.get('destination')
        options = cond.get('options')

        return cls(version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, source, destination, options)

