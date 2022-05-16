from struct import unpack

from .__constants import ETHER_TYPES


def llc(data: bytes) -> (list, tuple):
    if len(data) < 8:
        return [], ('MALFORMED', f"LLC requires at least 8 bytes, got {len(data)}")

    t = unpack('!BBB3sH', data[:8])
    r = [('dsap', t[0]),
         ('ssap', t[1]),
         ('control_field', t[2]),
         ('organization_code', t[3]),
         ('type', _type := t[4])]

    return r, (ETHER_TYPES.get(_type, 'UNKNOWN'), data[8:])


def summary(par: dict):
    return False
