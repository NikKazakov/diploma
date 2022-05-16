import struct
import extensions

from .dot11_header import Dot11Header


class Radiotap:
    __slots__ = 'version', 'pad', 'length', 'present', 'data_rate', 'channel_frequency', 'dbm_antenna_signal', \
                'antenna', 'flags', 'channel_flags', 'rx_flags', 'payload'
    name = 'radiotap'

    def __init__(self, version, pad, length, present, data_rate, channel_frequency, dbm_antenna_signal, antenna,
                 flags, channel_flags, rx_flags, payload=None):
        self.version = version
        self.pad = pad
        self.length = length
        self.present = present
        self.data_rate = data_rate
        self.channel_frequency = channel_frequency
        self.dbm_antenna_signal = dbm_antenna_signal
        self.antenna = antenna
        self.flags = flags
        self.channel_flags = channel_flags
        self.rx_flags = rx_flags
        
        self.payload = payload

    def summary(self):
        s = ''
        if self.channel_flags:
            if self.channel_flags.spectrum_5gz:
                s += '5 GHz '
            elif self.channel_flags.spectrum_2gz:
                s += '2.4 GHz '
        if self.channel_frequency:
            s += f'ch {calc_channel_number(self.channel_frequency)} '
        if self.dbm_antenna_signal:
            s += f'{self.dbm_antenna_signal} dbm'
        return s

    @classmethod
    def from_raw(cls, data):
        data_rate = None
        channel_frequency = None
        dbm_antenna_signal = None
        antenna = None
        flags = None
        channel_flags = None
        rx_flags = None

        if len(data) < 8:
            return extensions.MalformedPacketException(f"Radiotap requires at least 8 bytes, got {len(data)}")
        
        # get values for fields the packet has
        # Unpacks the first present dword
        version, pad, length, present = struct.unpack('<BBHI', data[:8])
        c = '0' * (32 - len(a := bin(present)[2:])) + a

        # Currently a placeholder for other present dwords
        c_else = '0' * (32 - len(a := bin(present)[2:])) + a
        last = 8
        while c_else[0] == '1':
            present_else = struct.unpack('<I', data[last:last+4])[0]
            c_else = '0' * (32 - len(a := bin(present_else)[2:])) + a
            last += 4

        radio_data = data[last:]

        if c[30] == '1':
            flags = Flags.from_raw(struct.unpack('<s', radio_data[:1])[0])
            radio_data = radio_data[1:]
        if c[29] == '1':
            data_rate = struct.unpack('<B', radio_data[:1])[0]
        radio_data = radio_data[1:]
        if c[28] == '1':
            channel_frequency, channel_flags = struct.unpack('<H2s', radio_data[:4])
            channel_flags = ChannelFlags.from_raw(channel_flags)
            radio_data = radio_data[4:]
        if c[26] == '1':
            dbm_antenna_signal = struct.unpack('<b', radio_data[:1])[0]
            radio_data = radio_data[1:]
        if c[20] == '1':
            antenna = struct.unpack('<B', radio_data[:1])[0]
            radio_data = radio_data[1:]
        if c[17] == '1':
            rx_flags = RxFlags.from_raw(struct.unpack('<2s', radio_data[:2])[0])
            radio_data = radio_data[2:]
        if c[12] == '1':
            mcs_information = struct.unpack('<BBB', radio_data[:3])
            radio_data = radio_data[3:]

        if flags.fcs_at_end:
            data = data[:-4]
        payload = Dot11Header.from_raw(data[length:])

        return cls(version, pad, length, present, data_rate, channel_frequency, dbm_antenna_signal, antenna, flags, 
                   channel_flags, rx_flags, payload)


class Flags:
    __slots__ = 'short_gi', 'bad_fcs', 'data_pad', 'fcs_at_end', 'fragmentation', 'wep', 'preamble', 'cfp'
    
    def __init__(self, short_gi, bad_fcs, data_pad, fcs_at_end, fragmentation, wep, preamble, cfp):
        self.short_gi = short_gi
        self.bad_fcs = bad_fcs
        self.data_pad = data_pad
        self.fcs_at_end = fcs_at_end
        self.fragmentation = fragmentation
        self.wep = wep
        self.preamble = preamble
        self.cfp = cfp
        
    @classmethod
    def from_raw(cls, data):
        short_gi = data[0] >> 7
        bad_fcs = (data[0] >> 6) & 1
        data_pad = (data[0] >> 5) & 1
        fcs_at_end = (data[0] >> 4) & 1
        fragmentation = (data[0] >> 3) & 1
        wep = (data[0] >> 2) & 1
        preamble = (data[0] >> 1) & 1
        cfp = data[0] & 1

        return cls(short_gi, bad_fcs, data_pad, fcs_at_end, fragmentation, wep, preamble, cfp)
    
        
class ChannelFlags:
    __slots__ = 'quarter_rate_channel', 'half_rate_channel', 'static_turbo', 'gsm', 'gfsk', 'dynamic_cck_ofdm', \
                'passive', 'spectrum_5gz', 'spectrum_2gz', 'ofdm', 'cck', 'turbo'
    
    def __init__(self, quarter_rate_channel, half_rate_channel, static_turbo, gsm, gfsk, dynamic_cck_ofdm, 
                 passive, spectrum_5gz, spectrum_2gz, ofdm, cck, turbo):
        self.quarter_rate_channel = quarter_rate_channel
        self.half_rate_channel = half_rate_channel
        self.static_turbo = static_turbo
        self.gsm = gsm
        self.gfsk = gfsk
        self.dynamic_cck_ofdm = dynamic_cck_ofdm
        self.passive = passive
        self.spectrum_5gz = spectrum_5gz
        self.spectrum_2gz = spectrum_2gz
        self.ofdm = ofdm
        self.cck = cck
        self.turbo = turbo
        
    @classmethod
    def from_raw(cls, data):
        quarter_rate_channel = data[1] >> 7
        half_rate_channel = (data[1] >> 6) & 1
        static_turbo = (data[1] >> 5) & 1
        gsm = (data[1] >> 4) & 1
        gfsk = (data[1] >> 3) & 1
        dynamic_cck_ofdm = (data[1] >> 2) & 1
        passive = (data[1] >> 1) & 1
        spectrum_5gz = data[1] & 1
        spectrum_2gz = (data[0] >> 7) & 1
        ofdm = (data[0] >> 6) & 1
        cck = (data[0] >> 5) & 1
        turbo = (data[0] >> 4) & 1

        return cls(quarter_rate_channel, half_rate_channel, static_turbo, gsm, gfsk, dynamic_cck_ofdm, passive, 
                   spectrum_5gz, spectrum_2gz, ofdm, cck, turbo)


class RxFlags:
    __slots__ = 'bad_plcp'
    
    def __init__(self, bad_plcp):
        self.bad_plcp = bad_plcp
        
    @classmethod
    def from_raw(cls, data):
        bad_plcp = (data[0] >> 1) & 1

        return cls(bad_plcp)


def calc_channel_number(freq):
    if 2412 <= freq <= 2472:
        return int((freq - 2) / 5 - 481)
    elif freq == 2484:
        return 14
    else:
        return int(freq / 5 - 1000)
