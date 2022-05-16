from struct import unpack, error
from extensions import int_to_ipv4

from .__constants import IP_PROTOS


def ipv4(data: bytes) -> (list, tuple):
    if len(data) < 20:
        return [], ('MALFORMED', f'IPv4 requires at least 20 bytes, got {len(data)}')

    t = unpack('!2sHHBBBBH4s4s', data[:20])

    r = [('version', t[0][0] >> 4),
         ('ihl', ihl := t[0][0] & 15),
         ('dscp', t[0][1] >> 6),
         ('ecn', t[0][1] & 3),
         ('total_length', t[1]),
         ('identification', t[2]),
         ('flags', t[3] >> 5),
         ('fragment_offset', (t[3] & 31) << 8 | t[4]),
         ('ttl', t[5]),
         ('protocol', proto := t[6]),
         ('header_checksum', t[7]),
         ('source', int.from_bytes(t[8], 'big')),
         ('destination', int.from_bytes(t[9], 'big'))]

    if ihl > 5:
        options_length = (ihl - 5) * 4
        try:
            r.append(('options', unpack(f'{options_length}s', data[20:20 + options_length])))
        except error as e:
            print(f"DEBUG got options of incorrect size: {e}")
            r.append(('options', unpack(f'{len(data) - 20}s', data[20:])))

    # save payload
    # if we know the next proto, parse the payload
    return r, (IP_PROTOS.get(proto, 'UNKNOWN'), data[ihl * 4:])


def summary(par: dict):
    return f"{int_to_ipv4(par['ipv4.source'])} -> {int_to_ipv4(par['ipv4.destination'])}"
