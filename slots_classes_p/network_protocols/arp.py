import struct
import extensions


class Arp:
    __slots__ = 'hardware_type', 'protocol_type', 'hardware_size', 'protocol_size', 'opcode', 'sender_mac', \
                'sender_ip', 'target_mac', 'target_ip', 'payload'
    name = 'arp'

    def __init__(self, hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip,
                 target_mac, target_ip, payload=None):
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

    def summary(self):
        return f'ARP {extensions.int_to_ipv4(self.sender_ip)} -> {extensions.int_to_ipv4(self.target_ip)}'

    @classmethod
    def from_raw(cls, data):
        if len(data) < 18:
            return extensions.MalformedPacketException(f"ARP requires at least 28 bytes, got {len(data)}")

        hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, \
        target_ip = struct.unpack('!HHBBH6sI6sI', data[:28])

        sender_mac = int.from_bytes(sender_mac, 'big')
        target_mac = int.from_bytes(target_mac, 'big')

        payload = data[28:]

        return cls(hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip,
                   target_mac, target_ip, payload)
