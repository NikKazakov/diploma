from struct import unpack
from extensions import get_bytes_to_mac, flatten_tuple


def dot11_header(data: bytes) -> (list, tuple):
    if len(data) < 10:
        return [], ('MALFORMED', f"dot11_header requires at least 10 bytes, got {len(data)}")

    t = unpack('!2sH6s', data[:10])
    frame_control, type_subtype, ds, fc_protected = _frame_control(t[0])
    r = flatten_tuple([('frame_control', t[0])], frame_control, 'frame_control')

    r.extend([('type_subtype', type_subtype),
              ('ds', ds),
              ('duration', t[1])])
    receiver = t[2]
    transmitter = None
    destination = None
    source = None

    if type_subtype in (28, 29, 30):  # type=1 & subtype=(12|13|14)
        last = 10
    elif type_subtype in (24, 26, 27):  # type=1 & subtype=(8|10|11)
        transmitter = unpack('!6s', data[10:16])[0]
        last = 16
    else:
        # TODO: remove exception when we account for all frame types
        try:
            transmitter, destination, seq = unpack('!6s6sH', data[10:24])
            r.append(('sequence_number', seq >> 4))
            r.append(('fragment_number', seq & 15))
        except Exception:
            print(f'Exception in dot11_header.py: type_subtype: {hex(type_subtype)}')

        if ds == 3:
            source = unpack('!6s', data[24:30])[0]
            last = 30
        else:
            last = 24

    r.append(('receiver', receiver))
    r.append(('transmitter', transmitter))
    if ds == 0:
        r.append(('destination', receiver))
        r.append(('source', transmitter))
        r.append(('bssid', destination))
        r.append(('sta_address', None))
    elif ds == 1:
        r.append(('destination', destination))
        r.append(('source', transmitter))
        r.append(('bssid', receiver))
        r.append(('sta_address', transmitter))
    elif ds == 2:
        r.append(('destination', receiver))
        r.append(('source', destination))
        r.append(('bssid', transmitter))
        r.append(('sta_address', receiver))
    elif ds == 3:
        r.append(('destination', destination))
        r.append(('source', source))
        r.append(('bssid', None))
        r.append(('sta_address', None))

    payload = ('UNKNOWN', data[last:])
    if type_subtype >> 4 == 0:  # type=0
        payload = ('dot11_management', data[last:], type_subtype & 0b1111)
    elif type_subtype in (32, 40):  # type=2 & subtype=(0|8)
        if type_subtype == 40:  # type=2 & subtype=8
            t, payload_type = _qos_control(unpack('!2s', data[last:last + 2])[0])
            r = flatten_tuple(r, t, 'qos_control')
            last += 2
            if payload_type == 0:
                payload = ('llc', data[last:])
        else:
            payload = ('llc', data[last:])
        if fc_protected:
            r = flatten_tuple(r, _ccmp(unpack('<8s', data[last:last + 8])[0]), 'ccmp')
            last += 8
            t = list(data[:last])
            t[1] = t[1] & 0b10111111
            payload = ('TO_DECRYPT', data[last:], bytes(t[:-8]))

    return r, payload


def summary(par: dict):
    inf = {0b00:
               {0b0000: 'Association Request',
                0b0001: 'Association Response',
                0b0010: 'Reassociation Request',
                0b0011: 'Reassociation Response',
                0b0100: 'Probe Request',
                0b0101: 'Probe Response',
                0b0110: 'Timing Advertisement',
                0b0111: 'RESERVED',
                0b1000: 'Beacon',
                0b1001: 'ATIM',
                0b1010: 'Disassociation',
                0b1011: 'Authentication',
                0b1100: 'Deauthentication',
                0b1101: 'Action',
                0b1110: 'Action No Ack',
                0b1111: 'RESERVED'},
           0b01:
               {0b0000: 'RESERVED',
                0b0001: 'RESERVED',
                0b0010: 'Trigger',
                0b0011: 'INVALID',
                0b0100: 'Beamforming Report Poll',
                0b0101: 'VHT/HE NDP Announcement',
                0b0110: 'Control Frame Extension',
                0b0111: 'Control Wrapper',
                0b1000: 'Block Ack Request',
                0b1001: 'Block Ack',
                0b1010: 'PS-Poll',
                0b1011: 'RTS',
                0b1100: 'CTS',
                0b1101: 'ACK',
                0b1110: 'CF-End',
                0b1111: 'CF-End + CF-ACK'},
           0b10:
               {0b0000: 'Data',
                0b0001: 'Data + CF-ACK',
                0b0010: 'Data + CF-Poll',
                0b0011: 'Data + CF-ACK + CF-Poll',
                0b0100: 'Null (no data)',
                0b0101: 'CF-ACK (no data)',
                0b0110: 'CF-Poll (no data)',
                0b0111: 'CF-ACK + CF-Poll (no data)',
                0b1000: 'QoS Data',
                0b1001: 'QoS Data + CF-ACK',
                0b1010: 'QoS Data + CF-Poll',
                0b1011: 'QoS Data + CF-ACK + CF-Poll',
                0b1100: 'QoS Null (no data)',
                0b1101: 'RESERVED',
                0b1110: 'QoS CF-Poll (no data)',
                0b1111: 'QoS CF-ACK + CF-Poll (no data)'},
           0b11:
               {0b0000: 'DMG Beacon',
                0b0001: 'RESERVED',
                0b0010: 'RESERVED',
                0b0011: 'RESERVED',
                0b0100: 'RESERVED',
                0b0101: 'RESERVED',
                0b0110: 'RESERVED',
                0b0111: 'RESERVED',
                0b1000: 'RESERVED',
                0b1001: 'RESERVED',
                0b1010: 'RESERVED',
                0b1011: 'RESERVED',
                0b1100: 'RESERVED',
                0b1101: 'RESERVED',
                0b1110: 'RESERVED',
                0b1111: 'RESERVED'}
           }

    # shortcuts
    t = par['dot11_header.frame_control.type']
    s = par['dot11_header.frame_control.subtype']
    src = get_bytes_to_mac(par['dot11_header.source'])
    dst = get_bytes_to_mac(par['dot11_header.destination'])

    if src is not None and dst is not None:
        return f"{inf[t][s]} {src} -> {dst}"
    elif dst is not None:
        return f"{inf[t][s]} {dst}"
    else:
        return f"WARNING: Strange .11 frame with no dst and src. Type_subtype: {int.to_bytes(t << 4 | s, 4)}"


def _frame_control(data: bytes) -> (list, int, int, int):
    return [('subtype', subtype := data[0] >> 4),
            ('type', _type := data[0] >> 2 & 3),
            ('version', data[0] & 3),
            ('to_ds', to_ds := data[1] & 1),
            ('from_ds', from_ds := data[1] >> 1 & 1),
            ('more_fragments', (data[1] >> 2) & 1),
            ('retry', (data[1] >> 3) & 1),
            ('pwr_mgt', (data[1] >> 4) & 1),
            ('more_data', (data[1] >> 5) & 1),
            ('protected', protected := data[1] >> 6 & 1),
            ('order', data[1] >> 7)], _type << 4 | subtype, from_ds << 1 | to_ds, protected


def _qos_control(data: bytes) -> (list, int):
    return [('priority', data[0] & 15),
            ('qos_bit_4', (data[0] >> 4) & 1),
            ('ack_policy', (data[0] >> 5) & 3),
            ('payload_type', payload_type := data[0] >> 7),
            ('second_byte', data[1])], payload_type


def _ccmp(data: bytes) -> list:
    pn = bytearray(6)
    pn[0:4] = data[7:3:-1]
    pn[4:6] = data[1::-1]
    return [('pn', bytes(pn)),
            ('ext_iv', (data[3] >> 5) & 1),
            ('key_id', data[3] >> 6)]
