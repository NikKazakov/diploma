import struct
import extensions

from .udp import Udp


class Ipv4:
    __slots__ = 'version', 'ihl', 'dscp', 'ecn', 'total_length', 'identification', 'flags', 'fragment_offset', 'ttl', \
                'protocol', 'header_checksum', 'source', 'destination', 'options', 'payload'
    name = 'ipv4'

    def __init__(self, version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol,
                 header_checksum, source, destination, options, payload=None):
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

    def summary(self):
        return f"{extensions.int_to_ipv4(self.source)} -> {extensions.int_to_ipv4(self.destination)}"

    @classmethod
    def from_raw(cls, data):
        if len(data) < 20:
            return extensions.MalformedPacketException(f'IPv4 requires at least 20 bytes, got {len(data)}')

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

        payload = data[ihl*4:]
        if protocol == 17:
            payload = Udp.from_raw(payload)

        return cls(version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol,
                   header_checksum, source, destination, options, payload)
