from struct import unpack, error
from extensions import flatten_tuple


def dot11_management(data: bytes, subtype: int) -> (list, tuple):
    t, data = _fixed(data, subtype)
    return flatten_tuple(flatten_tuple([], t, 'fixed'), _tagged(data), 'tagged'), ('UNKNOWN', b'')


def summary(par: dict):
    ret = ''
    if category_code := par.get('dot11_management.fixed.action.category_code'):
        try:
            inf = {3: 'Block Ack', 4: 'Public Action', 5: 'Radio Measurement', 10: 'WNM', 127: 'Vendor specific'}
            ret += f"Category: {inf[category_code]}"
        except KeyError:
            print(f'No description created for category code {category_code}')
    if authentication_seq := par.get('dot11_management.fixed.authentication_seq'):
        ret += f"Authentication SEQ: {authentication_seq}"
    if ssid := par.get('dot11_management.tagged.ssid'):
        ret += f"SSID:{str(ssid)[2:-1]}"
    return ret


def _fixed(_data: bytes, _subtype: int) -> (list, bytes):
    if _subtype in (0, 2):  # association request, reassociation request
        t = unpack('<2sH', _data[:4])
        r = [('listen_interval', t[1])]
        r = flatten_tuple(r, _capabilities(t[0]), 'capabilities')
        last = 4
        if _subtype == 2:
            r.append(('current_ap', unpack('6s', _data[4:10])))
            last = 10
    elif _subtype in (1, 3):  # association response, reassociation response
        t = unpack('<2sHH', _data[:6])
        r = [('status_code', t[1]),
             ('status_code', t[2] & 16383)]
        r = flatten_tuple(r, _capabilities(t[0]), 'capabilities')
        last = 6
    elif _subtype in (5, 8):  # probe response, beacon
        t = unpack('<QH2s', _data[:12])
        r = [('timestamp', t[0]),
             ('beacon_interval', t[1])]
        r = flatten_tuple(r, _capabilities(t[2]), 'capabilities')
        last = 12
    elif _subtype in (10, 12):  # disassociation, deauthentication
        r = [('reason_code', unpack('<H', _data[:2])[0])]
        last = 2
    elif _subtype == 11:  # authentication
        t = unpack('<HHH', _data[:6])
        r = [('authentication_algorithm', t[0]),
             ('authentication_seq', t[1]),
             ('status_code', t[2])]
        last = 6
    elif _subtype == 13:
        t, _data = _action(_data)
        r = flatten_tuple([], t, 'action')
        last = 0
    else:
        last = 0
        r = []

    return r, _data[last:]


def _capabilities(_data: bytes) -> list:
    return [('ess_capabilities', _data[0] & 1),
            ('ibss_status', (_data[0] >> 1) & 1),
            ('cfp_participation_capabilities', (((_data[1] >> 1) & 1) << 2) | (_data[0] >> 2) & 3),
            ('privacy', (_data[0] >> 4) & 1),
            ('short_preamble', (_data[0] >> 5) & 1),
            ('pbcc', (_data[0] >> 6) & 1),
            ('channel_agility', _data[0] >> 7),
            ('spectrum_management', _data[1] & 1),
            ('short_slot_time', (_data[1] >> 2) & 1),
            ('automatic_power_save_delivery', (_data[1] >> 3) & 1),
            ('radio_measurement', (_data[1] >> 4) & 1),
            ('dsss_ofdm', (_data[1] >> 5) & 1),
            ('delayed_block_ack', (_data[1] >> 6) & 1),
            ('immediate_block_ack', (_data[1] >> 7) & 1)]


def _action(_data: bytes) -> (list, bytes):
    category_code, action_code = unpack('<BB', _data[:2])
    r = [('category_code', category_code),
         ('action_code', action_code)]
    _data = _data[2:]
    if category_code == 3:
        if action_code == 0:
            t = unpack('<BHHH', _data[:7])
            r.extend([('dialog_token', t[0]),
                      ('block_ack_parameters', t[1]),
                      ('block_ack_timeout', t[2]),
                      ('block_ack_ssc', t[3])])
            _data = _data[7:]
        elif action_code == 1:
            t = unpack('<BHHH', _data[:7])
            r.extend([('dialog_token', t[0]),
                      ('status_code', t[1]),
                      ('block_ack_parameters', t[2]),
                      ('block_ack_timeout', t[3])])
            _data = _data[7:]
        elif action_code == 2:
            t = unpack('<HH', _data[:4])
            r.extend([('delete_block_ack', t[0]),
                      ('reason_code', t[1])])
            _data = _data[4:]
        else:
            r = []
            _data = b''
    elif category_code == 5:
        if action_code == 0:
            t = unpack('<BH', _data[:3])
            r.extend([('dialog_token', t[0]),
                      ('repetitions', t[1])])
            _data = _data[3:]
        elif action_code == 4:
            r.append(('dialog_token', unpack('<B', _data[:1])[0]))
            _data = _data[1:]
        else:
            r = []
            _data = b''
    else:
        r = []
        _data = b''

    return r, _data


def _tagged(data: bytes) -> list:
    r = []
    tags = {}
    while data:
        try:
            tag_number, tag_length = unpack('!BB', data[:2])
            try:
                tag_value = unpack(f'!{tag_length}s', data[2:tag_length + 2])[0]
            except error as e:
                # return extensions.MalformedPacketException(f"Is packet malformed? Couldn't unpack: {e}")
                tag_value = unpack(f'!{len(data)}s', data)[0]
        except:
            tag_number = 256
            tag_length = 256
            tag_value = unpack(f'!{len(data)}s', data)[0]
        tags[tag_number] = (tag_length, tag_value)
        # TODO: account for vendor-specific
        data = data[tag_length + 2:]
    
    if 0 in tags:
        if tags[0][1]:
            r.append(('ssid', tags[0][1]))  # If we have a name
        else:
            r.append(('ssid', b'Wildcard (Broadcast)'))
    if 1 in tags:
        r.append(('supported_rates', tags[1][1]))
    if 5 in tags:
        r.append(('traffic_indication_map', tags[5][1]))
    if 7 in tags:
        r.append(('country_information', tags[7][1]))
    if 32 in tags:
        r.append(('power_constraint', tags[32][1]))
    if 35 in tags:
        r.append(('tpc_report_transmit_power', tags[35][1]))
    if 45 in tags:
        r.append(('ht_capabilities', tags[45][1]))
    if 48 in tags:
        r.append(('rsn_information', tags[48][1]))
    if 61 in tags:
        r.append(('ht_information', tags[61][1]))
    if 127 in tags:
        r.append(('extended_capabilities', tags[127][1]))
    if 191 in tags:
        r.append(('vht_capabilities', tags[191][1]))
    if 192 in tags:
        r.append(('vht_operation', tags[192][1]))
    if 221 in tags:
        r.append(('vendor_specific', tags[221][1]))

    return r
