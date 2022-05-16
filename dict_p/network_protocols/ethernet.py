from struct import unpack
from extensions import get_bytes_to_mac

from .__constants import ETHER_TYPES


def ethernet(data: bytes) -> (list, tuple):
    if len(data) < 14:
        return [], ('MALFORMED', f"Ethernet requires at least 14 bytes, got {len(data)}")

    t = unpack('!6s6sH', data[:14])
    r = [('destination', t[0]),
         ('source', t[2]),
         ('length', length := t[3])]

    return r, (ETHER_TYPES.get(length, 'UNKNOWN'), data[14:])


def summary(par: dict):
    return f"Ether {get_bytes_to_mac(par['ethernet.source'])} -> {get_bytes_to_mac(par['ethernet.destination'])}"
