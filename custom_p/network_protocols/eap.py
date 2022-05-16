import struct
import extensions


class Eap:
    name = 'eap'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, code, id, length, type, identity, tls_length, tls_flags, payload=None):
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.identity = identity
        self.tls_length = tls_length
        self.tls_flags = tls_flags
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['code',
                'id',
                'length',
                'type',
                'identity',
                'tls_length',
                'tls_flags.length_included',
                'tls_flags.more_fragments',
                'tls_flags.start',
                'tls_flags.version',
                ]
        values = [self.code,
                  self.id,
                  self.length,
                  self.type,
                  self.identity,
                  self.tls_length,
                  self.tls_flags.length_included,
                  self.tls_flags.more_fragments,
                  self.tls_flags.start,
                  self.tls_flags.version,
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
        # initialize
        code = None
        id = None
        length = None
        type = None
        identity = None
        tls_length = None
        tls_flags = cls.TlsFlags(None, None, None, None)

        if len(data) < 4:
            return extensions.MalformedPacketException(f"EAP requires at least 4 bytes, got {len(data)}")
        
        # get values for fields the packet has
        code, id, length = struct.unpack('!BBH', data[:4])
        data = data[4:]
        if length > 4:
            type = struct.unpack('!B', data[:1])[0]

            if type == 1:
                identity = struct.unpack(f'!{length-5}s', data[1:length])[0]
                data = data[length:]
            elif type == 25:
                tls_flags = cls.TlsFlags.from_raw(data[1:2])
                if tls_flags.length_included:
                    tls_length = struct.unpack('!I', data[2:6])[0]
                    data = data[6:]
                else:
                    data = data[1:]

        # save payload
        # if we know the next proto, parse the payload
        payload = data

        return cls(code, id, length, type, identity, tls_length, tls_flags, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        code = cond.get('code')
        id = cond.get('id')
        length = cond.get('length')
        type = cond.get('type')
        identity = cond.get('identity')
        tls_length = cond.get('tls_length')

        # initialise complex/flag fields the user can access
        tls_flags = {}
        
        # collect complex fields into dictionaries
        for field in cond:
            pass
            if field.startswith('tls_flags.'):
                tls_flags[field.split('.', 1)[1]] = cond[field]
            
        # and initialise them
        tls_flags = cls.TlsFlags.from_dict(tls_flags)

        return cls(code, id, length, type, identity, tls_length, tls_flags)

    class TlsFlags:
        def __init__(self, length_included, more_fragments, start, version):
            self.length_included = length_included
            self.more_fragments = more_fragments
            self.start = start
            self.version = version
            
        @classmethod
        def from_raw(cls, data):
            # initialize
            length_included = None
            more_fragments = None
            start = None
            version = None
            
            # get values for fields the packet has
            length_included = data[0] >> 7
            more_fragments = (data[0] >> 6) & 1
            start = (data[0] >> 5) & 1
            version = data[0] & 7

            return cls(length_included, more_fragments, start, version)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            length_included = cond.get('length_included')
            more_fragments = cond.get('more_fragments')
            start = cond.get('start')
            version = cond.get('version')

            return cls(length_included, more_fragments, start, version)

