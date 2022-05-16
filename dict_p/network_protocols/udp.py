from struct import unpack

from .__constants import UDP_SERVICES


def udp(data: bytes) -> (list, tuple):
    if len(data) < 8:
        return [], ('MALFORMED', f"UDP requires at least 8 bytes, got {len(data)}")

    t = unpack('!HHHH', data[:8])
    r = [('source_port', t[0]),
         ('destination_port', dst_port := t[1]),
         ('length', length := t[2]),
         ('checksum', t[3])]

    return r, (UDP_SERVICES.get(dst_port, 'UNKNOWN'), data[8:length+8])


def summary(par: dict):
    return f"UDP {par['udp.destination_port']}"
