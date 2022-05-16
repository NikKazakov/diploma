from struct import unpack
from extensions import flatten_tuple


def radiotap(data: bytes) -> (list, tuple):
    if len(data) < 8:
        return [], ('MALFORMED', f"Radiotap requires at least 8 bytes, got {len(data)}")

    fcs_at_end = 0

    # Unpacks the first present dword
    t = unpack('<BBHI', data[:8])
    r = [('version', t[0]),
         ('pad', t[1]),
         ('length', (length := t[2])),
         ('present', (present := t[3]))]

    c = '0' * (32 - len(a := bin(present)[2:])) + a

    # Currently a placeholder for other present dwords
    c_else = '0' * (32 - len(a := bin(present)[2:])) + a
    last = 8
    while c_else[0] == '1':
        present_else = unpack('<I', data[last:last + 4])[0]
        c_else = '0' * (32 - len(a := bin(present_else)[2:])) + a
        last += 4

    radio_data = data[last:]

    if c[30] == '1':
        t, fcs_at_end = _flags(unpack('<s', radio_data[:1])[0])
        r = flatten_tuple(r, t, 'flags')
        radio_data = radio_data[1:]
    if c[29] == '1':
        r.append(('data_rate', unpack('<B', radio_data[:1])[0]))
    radio_data = radio_data[1:]
    if c[28] == '1':
        t = unpack('<H2s', radio_data[:4])
        r.append(('channel_frequency', t[0]))
        r = flatten_tuple(r, _channel_flags(t[1]), 'channel_flags')
        radio_data = radio_data[4:]
    if c[26] == '1':
        r.append(('dbm_antenna_signal', unpack('<b', radio_data[:1])[0]))
        radio_data = radio_data[1:]
    if c[20] == '1':
        r.append(('antenna', unpack('<B', radio_data[:1])[0]))
        radio_data = radio_data[1:]
    if c[17] == '1':
        r = flatten_tuple(r, _rx_flags(unpack('<2s', radio_data[:2])[0]), 'rx_flags')
        radio_data = radio_data[2:]
    if c[12] == '1':
        r.append(('mcs_information', unpack('<BBB', radio_data[:3])))
        radio_data = radio_data[3:]

    if fcs_at_end:
        data = data[:-4]

    return r, ('dot11_header', data[length:])


def summary(par: dict) -> str:
    t = []
    if par['radiotap.channel_flags.spectrum_5gz']:
        t.append('5 GHz')
    elif par['radiotap.channel_flags.spectrum_2gz']:
        t.append('2.4 GHz')
    if par['radiotap.channel_frequency']:
        t.append(f"ch {calc_channel_number(par['radiotap.channel_frequency'])}")
    if par['radiotap.dbm_antenna_signal']:
        t.append(f"{par['radiotap.dbm_antenna_signal']} dbm")
    return ' '.join(t)


def calc_channel_number(freq):
    if 2412 <= freq <= 2472:
        return int((freq - 2) / 5 - 481)
    elif freq == 2484:
        return 14
    else:
        return int(freq / 5 - 1000)


def _flags(data: bytes) -> (list, int):
    return [('short_gi', data[0] >> 7),
            ('bad_fcs', (data[0] >> 6) & 1),
            ('data_pad', (data[0] >> 5) & 1),
            ('fcs_at_end', fcs_at_end := data[0] >> 4 & 1),
            ('fragmentation', (data[0] >> 3) & 1),
            ('wep', (data[0] >> 2) & 1),
            ('preamble', (data[0] >> 1) & 1),
            ('cfp', data[0] & 1)], fcs_at_end


def _channel_flags(data: bytes) -> list:
    return [('quarter_rate_channel', data[1] >> 7),
            ('half_rate_channel', (data[1] >> 6) & 1),
            ('static_turbo', (data[1] >> 5) & 1),
            ('gsm', (data[1] >> 4) & 1),
            ('gfsk', (data[1] >> 3) & 1),
            ('dynamic_cck_ofdm', (data[1] >> 2) & 1),
            ('passive', (data[1] >> 1) & 1),
            ('spectrum_5gz', data[1] & 1),
            ('spectrum_2gz', (data[0] >> 7) & 1),
            ('ofdm', (data[0] >> 6) & 1),
            ('cck', (data[0] >> 5) & 1),
            ('turbo', (data[0] >> 4) & 1)]


def _rx_flags(data: bytes) -> list:
    return [('bad_plcp', (data[0] >> 1) & 1)]
