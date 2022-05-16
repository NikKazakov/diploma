import struct
import extensions


class Arp:
    name = 'arp'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip, payload=None):
        self.hardware_type = hardware_type
        self.protocol_type = protocol_type
        self.hardware_size = hardware_size
        self.protocol_size = protocol_size
        self.opcode = opcode
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['hardware_type',
                'protocol_type',
                'hardware_size',
                'protocol_size',
                'opcode',
                'sender_mac',
                'sender_ip',
                'target_mac',
                'target_ip',
                ]
        values = [self.hardware_type,
                  self.protocol_type,
                  self.hardware_size,
                  self.protocol_size,
                  self.opcode,
                  self.sender_mac,
                  self.sender_ip,
                  self.target_mac,
                  self.target_ip,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'sender_mac' in ret:
                ret['sender_mac'] = extensions.int_to_mac(ret['sender_mac'])
            if 'sender_ip' in ret:
                ret['sender_ip'] = extensions.int_to_ipv4(ret['sender_ip'])
            if 'target_mac' in ret:
                ret['target_mac'] = extensions.int_to_mac(ret['target_mac'])
            if 'target_ip' in ret:
                ret['target_ip'] = extensions.int_to_ipv4(ret['target_ip'])
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

    def get_sender_mac(self):
        return extensions.int_to_mac(self.sender_mac)

    def get_sender_ip(self):
        return extensions.int_to_ipv4(self.sender_ip)

    def get_target_mac(self):
        return extensions.int_to_mac(self.target_mac)

    def get_target_ip(self):
        return extensions.int_to_ipv4(self.target_ip)

    def summary(self):
        return f'ARP {self.get_sender_ip()} -> {self.get_target_ip()}'

    @classmethod
    def from_raw(cls, data):
        # initialize
        hardware_type = None
        protocol_type = None
        hardware_size = None
        protocol_size = None
        opcode = None
        sender_mac = None
        sender_ip = None
        target_mac = None
        target_ip = None

        if len(data) < 18:
            return extensions.MalformedPacketException(f"ARP requires at least 28 bytes, got {len(data)}")
        
        # get values for fields the packet has
        hardware_type, protocol_type, hardware_size, protocol_size, opcode, \
        sender_mac, sender_ip, target_mac, target_ip = struct.unpack('!HHBBH6sI6sI', data[:28])

        sender_mac = int.from_bytes(sender_mac, 'big')
        target_mac = int.from_bytes(target_mac, 'big')

        # save payload
        # if we know the next proto, parse the payload
        payload = data[28:]

        return cls(hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        hardware_type = cond.get('hardware_type')
        protocol_type = cond.get('protocol_type')
        hardware_size = cond.get('hardware_size')
        protocol_size = cond.get('protocol_size')
        opcode = cond.get('opcode')
        sender_mac = cond.get('sender_mac')
        sender_ip = cond.get('sender_ip')
        target_mac = cond.get('target_mac')
        target_ip = cond.get('target_ip')

        return cls(hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip)

