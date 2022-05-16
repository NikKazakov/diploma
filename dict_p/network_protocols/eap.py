from struct import unpack
from extensions import flatten_tuple


def eap(data: bytes) -> (list, tuple):
    if len(data) < 4:
        return [], ('MALFORMED', f"EAP requires at least 4 bytes, got {len(data)}")

    t = unpack('!BBH', data[:4])
    r = [('code', t[0]),
         ('id', t[1]),
         ('length', length := t[2])]
    data = data[4:]
    if length > 4:
        r.append(('type', _type := unpack('!B', data[:1])[0]))
        if _type == 1:
            r.append(('identity', unpack(f'!{length - 5}s', data[1:length])[0]))
            data = data[length:]
        elif _type == 25:
            t, length_included = _tls_flags(data[1:2])
            r = flatten_tuple(r, t, 'tls_flags')
            if length_included:
                r.append(('tls_length', unpack('!I', data[2:6])[0]))
                data = data[6:]
            else:
                data = data[1:]

    return r, ('UNKNOWN', data)


def summary(par: dict):
    inf = {'code': {1: 'Request', 2: 'Response', 3: 'Success'}, 'type': {1: 'Identity', 25: 'Protected EAP'}}
    code = par['eap.code']
    _type = par['eap.type']
    ret = "EAP "
    try:
        ret += f"{inf['code'][code]}"
    except:
        print(f'No description for EAP code: {code}')
        ret += f'code {code}'
    if _type:
        try:
            ret += f", {inf['type'][_type]}"
        except:
            print(f'No description for EAP type: {_type}')
            ret += f'type {_type}'
    return False


def _tls_flags(data: bytes) -> (list, int):
    return [('length_included', length_included := data[0] >> 7),
            ('more_fragments', (data[0] >> 6) & 1),
            ('start', (data[0] >> 5) & 1),
            ('version', data[0] & 7)], length_included
