import struct
import extensions

from .dot11_header import Dot11Header


class Radiotap:
    name = 'radiotap'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, version, pad, length, present, data_rate, channel_frequency, dbm_antenna_signal, antenna, flags, channel_flags, rx_flags, payload=None):
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

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['version',
                'pad',
                'length',
                'present',
                'data_rate',
                'channel_frequency',
                'dbm_antenna_signal',
                'antenna',
                'flags.short_gi',
                'flags.bad_fcs',
                'flags.data_pad',
                'flags.fcs_at_end',
                'flags.fragmentation',
                'flags.wep',
                'flags.preamble',
                'flags.cfp',
                'channel_flags.quarter_rate_channel',
                'channel_flags.half_rate_channel',
                'channel_flags.static_turbo',
                'channel_flags.gsm',
                'channel_flags.gfsk',
                'channel_flags.dynamic_cck_ofdm',
                'channel_flags.passive',
                'channel_flags.spectrum_5gz',
                'channel_flags.spectrum_2gz',
                'channel_flags.ofdm',
                'channel_flags.cck',
                'channel_flags.turbo',
                'rx_flags.bad_plcp',
                ]
        values = [self.version,
                  self.pad,
                  self.length,
                  self.present,
                  self.data_rate,
                  self.channel_frequency,
                  self.dbm_antenna_signal,
                  self.antenna,
                  self.flags.short_gi,
                  self.flags.bad_fcs,
                  self.flags.data_pad,
                  self.flags.fcs_at_end,
                  self.flags.fragmentation,
                  self.flags.wep,
                  self.flags.preamble,
                  self.flags.cfp,
                  self.channel_flags.quarter_rate_channel,
                  self.channel_flags.half_rate_channel,
                  self.channel_flags.static_turbo,
                  self.channel_flags.gsm,
                  self.channel_flags.gfsk,
                  self.channel_flags.dynamic_cck_ofdm,
                  self.channel_flags.passive,
                  self.channel_flags.spectrum_5gz,
                  self.channel_flags.spectrum_2gz,
                  self.channel_flags.ofdm,
                  self.channel_flags.cck,
                  self.channel_flags.turbo,
                  self.rx_flags.bad_plcp,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'dbm_antenna_signal' in ret:
                ret['dbm_antenna_signal'] = f"{ret['dbm_antenna_signal']} Dbm"
            if 'channel_frequency' in ret:
                ret['channel'] = calc_channel_number(ret['channel_frequency'])
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

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
        # initialize
        version = None
        pad = None
        length = None
        present = None
        data_rate = None
        channel_frequency = None
        dbm_antenna_signal = None
        antenna = None
        flags = cls.Flags(None, None, None, None, None, None, None, None)
        channel_flags = cls.ChannelFlags(None, None, None, None, None, None, None, None, None, None, None, None)
        rx_flags = cls.RxFlags(None)

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
            flags = cls.Flags.from_raw(struct.unpack('<s', radio_data[:1])[0])
            radio_data = radio_data[1:]
        if c[29] == '1':
            data_rate = struct.unpack('<B', radio_data[:1])[0]
        radio_data = radio_data[1:]
        if c[28] == '1':
            channel_frequency, channel_flags = struct.unpack('<H2s', radio_data[:4])
            channel_flags = cls.ChannelFlags.from_raw(channel_flags)
            radio_data = radio_data[4:]
        if c[26] == '1':
            dbm_antenna_signal = struct.unpack('<b', radio_data[:1])[0]
            radio_data = radio_data[1:]
        if c[20] == '1':
            antenna = struct.unpack('<B', radio_data[:1])[0]
            radio_data = radio_data[1:]
        if c[17] == '1':
            rx_flags = cls.RxFlags.from_raw(struct.unpack('<2s', radio_data[:2])[0])
            radio_data = radio_data[2:]
        if c[12] == '1':
            mcs_information = struct.unpack('<BBB', radio_data[:3])
            radio_data = radio_data[3:]

        # save payload
        # if we know the next proto, parse the payload
        if flags.fcs_at_end:
            data = data[:-4]
        payload = Dot11Header.from_raw(data[length:])

        return cls(version, pad, length, present, data_rate, channel_frequency, dbm_antenna_signal, antenna, flags, channel_flags, rx_flags, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        version = cond.get('version')
        pad = cond.get('pad')
        length = cond.get('length')
        present = cond.get('present')
        data_rate = cond.get('data_rate')
        channel_frequency = cond.get('channel_frequency')
        dbm_antenna_signal = cond.get('dbm_antenna_signal')
        antenna = cond.get('antenna')

        # initialise complex/flag fields the user can access
        flags = {}
        channel_flags = {}
        rx_flags = {}
        
        # collect complex fields into dictionaries
        for field in cond:
            pass
            if field.startswith('flags.'):
                flags[field.split('.', 1)[1]] = cond[field]
            if field.startswith('channel_flags.'):
                channel_flags[field.split('.', 1)[1]] = cond[field]
            if field.startswith('rx_flags.'):
                rx_flags[field.split('.', 1)[1]] = cond[field]
            
        # and initialise them
        flags = cls.Flags.from_dict(flags)
        channel_flags = cls.ChannelFlags.from_dict(channel_flags)
        rx_flags = cls.RxFlags.from_dict(rx_flags)

        return cls(version, pad, length, present, data_rate, channel_frequency, dbm_antenna_signal, antenna, flags, channel_flags, rx_flags)

    class Flags:
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
            # initialize
            short_gi = None
            bad_fcs = None
            data_pad = None
            fcs_at_end = None
            fragmentation = None
            wep = None
            preamble = None
            cfp = None
            
            # get values for fields the packet has
            short_gi = data[0] >> 7
            bad_fcs = (data[0] >> 6) & 1
            data_pad = (data[0] >> 5) & 1
            fcs_at_end = (data[0] >> 4) & 1
            fragmentation = (data[0] >> 3) & 1
            wep = (data[0] >> 2) & 1
            preamble = (data[0] >> 1) & 1
            cfp = data[0] & 1

            return cls(short_gi, bad_fcs, data_pad, fcs_at_end, fragmentation, wep, preamble, cfp)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            short_gi = cond.get('short_gi')
            bad_fcs = cond.get('bad_fcs')
            data_pad = cond.get('data_pad')
            fcs_at_end = cond.get('fcs_at_end')
            fragmentation = cond.get('fragmentation')
            wep = cond.get('wep')
            preamble = cond.get('preamble')
            cfp = cond.get('cfp')

            return cls(short_gi, bad_fcs, data_pad, fcs_at_end, fragmentation, wep, preamble, cfp)

    class ChannelFlags:
        def __init__(self, quarter_rate_channel, half_rate_channel, static_turbo, gsm, gfsk, dynamic_cck_ofdm, passive, spectrum_5gz, spectrum_2gz, ofdm, cck, turbo):
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
            # initialize
            quarter_rate_channel = None
            half_rate_channel = None
            static_turbo = None
            gsm = None
            gfsk = None
            dynamic_cck_ofdm = None
            passive = None
            spectrum_5gz = None
            spectrum_2gz = None
            ofdm = None
            cck = None
            turbo = None

            # get values for fields the packet has
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

            return cls(quarter_rate_channel, half_rate_channel, static_turbo, gsm, gfsk, dynamic_cck_ofdm, passive, spectrum_5gz, spectrum_2gz, ofdm, cck, turbo)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            quarter_rate_channel = cond.get('quarter_rate_channel')
            half_rate_channel = cond.get('half_rate_channel')
            static_turbo = cond.get('static_turbo')
            gsm = cond.get('gsm')
            gfsk = cond.get('gfsk')
            dynamic_cck_ofdm = cond.get('dynamic_cck_ofdm')
            passive = cond.get('passive')
            spectrum_5gz = cond.get('spectrum_5gz')
            spectrum_2gz = cond.get('spectrum_2gz')
            ofdm = cond.get('ofdm')
            cck = cond.get('cck')
            turbo = cond.get('turbo')

            return cls(quarter_rate_channel, half_rate_channel, static_turbo, gsm, gfsk, dynamic_cck_ofdm, passive, spectrum_5gz, spectrum_2gz, ofdm, cck, turbo)

    class RxFlags:
        def __init__(self, bad_plcp):
            self.bad_plcp = bad_plcp
            
        @classmethod
        def from_raw(cls, data):
            # initialize
            bad_plcp = None
            
            # get values for fields the packet has
            bad_plcp = (data[0] >> 1) & 1

            return cls(bad_plcp)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            bad_plcp = cond.get('bad_plcp')

            return cls(bad_plcp)


def calc_channel_number(freq):
    if 2412 <= freq <= 2472:
        return int((freq - 2) / 5 - 481)
    elif freq == 2484:
        return 14
    else:
        return int(freq / 5 - 1000)
