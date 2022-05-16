from struct import unpack
from extensions import flatten_tuple


def dot1x_authentication(data: bytes) -> (list, tuple):
    if len(data) < 4:
        return [], ('MALFORMED', f"1x_auth requires at least 4 bytes, got {len(data)}")

    t = unpack('!BBH', data[:4])
    r = [('version', t[0]),
         ('type', _type := t[1]),
         ('length', length := t[2])]

    data = data[4:length + 4]

    if _type == 0:  # EAP packet
        return r, ('eap', data)
    elif _type == 3:  # key
        t = unpack('!B2sHQ32s16s8s8s16sH', data[:95])
        r.extend([('key_descriptor_type', t[0]),
                  ('key_length', t[2]),
                  ('replay_counter', t[3]),
                  ('wpa_key_nonce', t[4]),
                  ('key_iv', t[5]),
                  ('wpa_key_rsc', t[6]),
                  ('wpa_key_id', t[7]),
                  ('wpa_key_mic', t[8]),
                  ('wpa_key_data_length', wpa_key_data_length := t[9])])
        r = flatten_tuple(r, _key_information(t[1]), 'key_information')
        if wpa_key_data_length:
            r.append(('wpa_key_data', unpack(f'!{wpa_key_data_length}s', data[95:95+wpa_key_data_length])))
        return r, ('UNKNOWN', data[95+wpa_key_data_length:])
    else:
        print(f"WARNING: got 1x packet with unknown yet type: {_type}")
        return r, ('UNKNOWN', data)


def summary(par: dict):
    if par['dot1x_authentication.type'] == 3:
        return 'EAPOL RSN Key'
    return False


def _key_information(data: bytes) -> list:
    return [('key_descriptor_version', data[1] & 7),
            ('key_type', (data[1] >> 3) & 1),
            ('key_index', (data[1] >> 4) & 3),
            ('install', (data[1] >> 6) & 1),
            ('key_ack', data[1] >> 7),
            ('key_mic', data[0] & 1),
            ('secure', (data[0] >> 1) & 1),
            ('error', (data[0] >> 2) & 1),
            ('request', (data[0] >> 3) & 1),
            ('encrypted_key_data', (data[0] >> 4) & 1),
            ('smk_message', (data[0] >> 5) & 1)]
