from struct import unpack
from extensions import int_to_ipv4


def arp(data: bytes) -> (list, tuple):
    if len(data) < 28:
        return [], ('MALFORMED', f"ARP requires at least 28 bytes, got {len(data)}")

    t = unpack('!HHBBH6sI6sI', data[:28])
    return [('hardware_type', t[0]),
            ('protocol_type', t[1]),
            ('hardware_size', t[2]),
            ('protocol_size', t[3]),
            ('opcode',t[4]),
            ('sender_mac', t[5]),
            ('sender_ip', t[6]),
            ('target_mac', t[7]),
            ('target_ip',t[8])], ('UNKNOWN', data[28:])


def summary(par: dict):
    return f"ARP {int_to_ipv4(par['arp.sender_ip'])} -> {int_to_ipv4(par['arp.target_ip'])}"
