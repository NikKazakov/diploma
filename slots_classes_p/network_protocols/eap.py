import struct
import extensions


class Eap:
    __slots__ = 'code', 'id', 'length', 'type', 'identity', 'tls_length', 'tls_flags', 'payload'
    name = 'eap'

    def __init__(self, code, id, length, type, identity, tls_length, tls_flags, payload=None):
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.identity = identity
        self.tls_length = tls_length
        self.tls_flags = tls_flags
        
        self.payload = payload

    def summary(self):
        inf = {'code': {1: 'Request', 2: 'Response', 3: 'Success'}, 'type': {1: 'Identity', 25: 'Protected EAP'}}
        ret = "EAP "
        try:
            ret += f"{inf['code'][self.code]}"
        except:
            print(f'No description for EAP code: {self.code}')
            ret += f'code {self.code}'
        if self.type:
            try:
                ret += f", {inf['type'][self.type]}"
            except:
                print(f'No description for EAP type: {self.type}')
                ret += f'type {self.type}'
        return False

    @classmethod
    def from_raw(cls, data):
        type = None
        identity = None
        tls_length = None
        tls_flags = None

        if len(data) < 4:
            return extensions.MalformedPacketException(f"EAP requires at least 4 bytes, got {len(data)}")

        code, id, length = struct.unpack('!BBH', data[:4])
        data = data[4:]
        if length > 4:
            type = struct.unpack('!B', data[:1])[0]

            if type == 1:
                identity = struct.unpack(f'!{length-5}s', data[1:length])[0]
                data = data[length:]
            elif type == 25:
                tls_flags = TlsFlags.from_raw(data[1:2])
                if tls_flags.length_included:
                    tls_length = struct.unpack('!I', data[2:6])[0]
                    data = data[6:]
                else:
                    data = data[1:]

        payload = data

        return cls(code, id, length, type, identity, tls_length, tls_flags, payload)


class TlsFlags:
    __slots__ = 'length_included', 'more_fragments', 'start', 'version'
    
    def __init__(self, length_included, more_fragments, start, version):
        self.length_included = length_included
        self.more_fragments = more_fragments
        self.start = start
        self.version = version
        
    @classmethod
    def from_raw(cls, data):
        length_included = data[0] >> 7
        more_fragments = (data[0] >> 6) & 1
        start = (data[0] >> 5) & 1
        version = data[0] & 7

        return cls(length_included, more_fragments, start, version)
