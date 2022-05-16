import struct
import extensions

from .dot11_management import Dot11Management
from .llc import Llc


class Dot11Header:
    name = 'dot11_header'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, duration, receiver, transmitter, destination, sequence_number, fragment_number, address_4,
                 frame_control, qos_control, ccmp, payload=None, source=None, bssid=None, sta_address=None):
        self.duration = duration
        self.receiver = receiver
        self.transmitter = transmitter
        self.destination = destination
        self.sequence_number = sequence_number
        self.fragment_number = fragment_number
        self.address_4 = address_4
        self.frame_control = frame_control
        self.qos_control = qos_control
        self.ccmp = ccmp

        if frame_control.to_ds is not None:
            ds = frame_control.from_ds << 1 | frame_control.to_ds
        else:
            ds = None

        self.source = source
        self.bssid = bssid
        self.sta_address = sta_address
        if source is None and bssid is None and sta_address is None:
            if ds == 0:
                self.source = transmitter
                self.bssid = destination
                self.sta_address = None
                self.destination = receiver
            elif ds == 1:
                self.source = transmitter
                self.bssid = receiver
                self.sta_address = transmitter
            elif ds == 2:
                self.source = destination
                self.bssid = transmitter
                self.sta_address = receiver
                self.destination = receiver
            elif ds == 3:
                self.source = address_4
                self.bssid = None
                self.sta_address = None

        self.payload = payload

    def get_all_fields(self, all=False, repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['duration',
                'receiver',
                'transmitter',
                'destination',
                'sequence_number',
                'fragment_number',
                'address_4',
                'frame_control.version',
                'frame_control.type',
                'frame_control.subtype',
                'frame_control.to_ds',
                'frame_control.from_ds',
                'frame_control.more_fragments',
                'frame_control.retry',
                'frame_control.pwr_mgt',
                'frame_control.more_data',
                'frame_control.protected',
                'frame_control.order',
                'qos_control.priority',
                'qos_control.qos_bit_4',
                'qos_control.ack_policy',
                'qos_control.payload_type',
                'qos_control.second_byte',
                'ccmp.pn',
                'ccmp.ext_iv',
                'ccmp.key_id',
                'source',
                'bssid',
                'sta_address'
                ]
        values = [self.duration,
                  self.receiver,
                  self.transmitter,
                  self.destination,
                  self.sequence_number,
                  self.fragment_number,
                  self.address_4,
                  self.frame_control.version,
                  self.frame_control.type,
                  self.frame_control.subtype,
                  self.frame_control.to_ds,
                  self.frame_control.from_ds,
                  self.frame_control.more_fragments,
                  self.frame_control.retry,
                  self.frame_control.pwr_mgt,
                  self.frame_control.more_data,
                  self.frame_control.protected,
                  self.frame_control.order,
                  self.qos_control.priority,
                  self.qos_control.qos_bit_4,
                  self.qos_control.ack_policy,
                  self.qos_control.payload_type,
                  self.qos_control.second_byte,
                  self.ccmp.pn,
                  self.ccmp.ext_iv,
                  self.ccmp.key_id,
                  self.source,
                  self.bssid,
                  self.sta_address
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'receiver' in ret:
                ret['receiver'] = extensions.int_to_mac(ret['receiver'])
            if 'transmitter' in ret:
                ret['transmitter'] = extensions.int_to_mac(ret['transmitter'])
            if 'destination' in ret:
                ret['destination'] = extensions.int_to_mac(ret['destination'])
            if 'address_4' in ret:
                ret['address_4'] = extensions.int_to_mac(ret['address_4'])
            if 'source' in ret:
                ret['source'] = extensions.int_to_mac(ret['source'])
            if 'bssid' in ret:
                ret['bssid'] = extensions.int_to_mac(ret['bssid'])
            if 'sta_address' in ret:
                ret['sta_address'] = extensions.int_to_mac(ret['sta_address'])
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            if field.startswith('fc.'):
                n_cond[f'frame_control.{field[3:]}'] = cond[field]
            elif field.startswith('qos.'):
                n_cond[f'qos_control.{field[4:]}'] = cond[field]
            elif field == 'ds':
                n_cond['ds_status'] = cond[field]
            else:
                n_cond[field] = cond[field]
        return n_cond

    def get_src(self):
        return extensions.int_to_mac(self.source)

    def get_dst(self):
        return extensions.int_to_mac(self.destination)

    def get_bssid(self):
        return extensions.int_to_mac(self.bssid)

    def get_sta(self):
        return extensions.int_to_mac(self.sta_address)

    def summary(self):
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
        t = self.frame_control.type
        s = self.frame_control.subtype
        f = self.get_all_fields(repr=True)

        if 'source' in f and 'destination' in f:
            return f"{inf[t][s]} {f['source']} -> {f['destination']}"
        elif 'destination' in f:
            return f"{inf[t][s]} {f['destination']}"
        return False

    @classmethod
    def from_raw(cls, data):
        # initialize
        duration = None
        receiver = None
        transmitter = None
        destination = None
        sequence_number = None
        fragment_number = None
        address_4 = None
        frame_control = cls.FrameControl(None, None, None, None, None, None, None, None, None, None, None)
        qos_control = cls.QosControl(None, None, None, None, None)
        ccmp = cls.Ccmp(None, None, None)

        if len(data) < 10:
            return extensions.MalformedPacketException(f".11 requires at least 10 bytes, got {len(data)}")

        # get values for fields the packet has
        frame_control, duration, receiver = struct.unpack('!2sH6s', data[:10])
        frame_control = cls.FrameControl.from_raw(frame_control)
        receiver = int.from_bytes(receiver, 'big')
        transmitter = None
        destination = None
        sequence_number = None
        fragment_number = None
        address_4 = None
        qos_control = cls.QosControl(None, None, None, None, None)
        ccmp = cls.Ccmp(None, None, None)

        if frame_control.type == 1 and (frame_control.subtype == 12 or
                                        frame_control.subtype == 13 or
                                        frame_control.subtype == 14):
            last = 10
        elif frame_control.type == 1 and (frame_control.subtype == 8 or
                                          frame_control.subtype == 10 or
                                          frame_control.subtype == 11):
            transmitter = int.from_bytes(struct.unpack('!6s', data[10:16])[0], 'big')
            last = 16
        else:
            # TODO: remove exception when we account for all frame types
            try:
                transmitter, destination, sequence_fragment = struct.unpack('!6s6sH', data[10:24])
            except Exception:
                print(f'type: {frame_control.type} subtype: {frame_control.subtype}')
            transmitter = int.from_bytes(transmitter, 'big')
            destination = int.from_bytes(destination, 'big')
            sequence_number = sequence_fragment >> 4
            fragment_number = sequence_fragment & 15
            if frame_control.to_ds and frame_control.from_ds:
                address_4 = int.from_bytes(struct.unpack('!6s', data[24:30])[0], 'big')
                last = 30
            else:
                last = 24

        if frame_control.type == 2 and frame_control.subtype == 8:
            qos_control = cls.QosControl.from_raw(struct.unpack('!2s', data[last:last + 2])[0])
            last += 2
        if frame_control.protected:
            ccmp = cls.Ccmp.from_raw(struct.unpack('<8s', data[last:last + 8])[0])
            last += 8

        # save payload
        # if we know the next proto, parse the payload
        data = data[last:]

        header = cls(duration, receiver, transmitter, destination, sequence_number, fragment_number, address_4,
                    frame_control, qos_control, ccmp)

        if frame_control.type == 0:
            header.payload = Dot11Management.from_raw(data, frame_control.subtype)
        elif frame_control.type == 2 and (frame_control.subtype == 0 or
                                          frame_control.subtype == 8):
            if frame_control.protected:
                return header
            if frame_control.subtype == 0 or qos_control.payload_type == 0:
                header.payload = Llc.from_raw(data)
            else:
                header.payload = data

        return header

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        duration = cond.get('duration')
        receiver = cond.get('receiver')
        transmitter = cond.get('transmitter')
        destination = cond.get('destination')
        sequence_number = cond.get('sequence_number')
        fragment_number = cond.get('fragment_number')
        address_4 = cond.get('address_4')

        # initalize alternative fields user can access
        subtype = cond.get('subtype')
        type = cond.get('type')
        type_subtype = cond.get('type_subtype')
        version = cond.get('version')
        ds = cond.get('ds_status')
        source = cond.get('source')
        bssid = cond.get('bssid')
        sta_address = cond.get('sta_address')

        # initialise complex/flag fields the user can access
        frame_control = {}
        qos_control = {}
        ccmp = {}

        # collect complex fields into dictionaries
        for field in cond:
            if field.startswith('frame_control.'):
                frame_control[field.split('.', 1)[1]] = cond[field]
            if field.startswith('qos_control.'):
                qos_control[field.split('.', 1)[1]] = cond[field]
            if field.startswith('ccmp.'):
                ccmp[field.split('.', 1)[1]] = cond[field]

        # and initialise them
        frame_control = cls.FrameControl.from_dict(frame_control)
        qos_control = cls.QosControl.from_dict(qos_control)
        ccmp = cls.Ccmp.from_dict(ccmp)

        # re-initialise additional/standard stuff users don't have access to
        if ds is not None:
            frame_control.to_ds = extensions.Int(ds & 1)
            frame_control.to_ds.not_flag = ds.not_flag
            frame_control.from_ds = extensions.Int(ds >> 1)
            frame_control.from_ds.not_flag = ds.not_flag
        if type is not None:
            frame_control.type = type
        if subtype is not None:
            frame_control.subtype = subtype
        if type_subtype is not None:
            frame_control.type = extensions.Int(type_subtype >> 4)
            frame_control.type.not_flag = type_subtype.not_flag
            frame_control.subtype = extensions.Int(type_subtype & 15)
            frame_control.subtype.not_flag = type_subtype.not_flag
        if version is not None:
            frame_control.version = version

        return cls(duration, receiver, transmitter, destination, sequence_number, fragment_number, address_4,
                   frame_control, qos_control, ccmp, None, source, bssid, sta_address)

    class FrameControl:
        def __init__(self, version, type, subtype, to_ds, from_ds, more_fragments, retry, pwr_mgt, more_data, protected,
                     order):
            self.version = version
            self.type = type
            self.subtype = subtype
            self.to_ds = to_ds
            self.from_ds = from_ds
            self.more_fragments = more_fragments
            self.retry = retry
            self.pwr_mgt = pwr_mgt
            self.more_data = more_data
            self.protected = protected
            self.order = order

        @classmethod
        def from_raw(cls, data):
            # initialize
            version = None
            type = None
            subtype = None
            to_ds = None
            from_ds = None
            more_fragments = None
            retry = None
            pwr_mgt = None
            more_data = None
            protected = None
            order = None

            # get values for fields the packet has
            subtype = data[0] >> 4
            type = (data[0] >> 2) & 3
            version = data[0] & 3
            to_ds = data[1] & 1
            from_ds = (data[1] >> 1) & 1
            more_fragments = (data[1] >> 2) & 1
            retry = (data[1] >> 3) & 1
            pwr_mgt = (data[1] >> 4) & 1
            more_data = (data[1] >> 5) & 1
            protected = (data[1] >> 6) & 1
            order = data[1] >> 7

            return cls(version, type, subtype, to_ds, from_ds, more_fragments, retry, pwr_mgt, more_data, protected,
                       order)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            version = cond.get('version')
            type = cond.get('type')
            subtype = cond.get('subtype')
            to_ds = cond.get('to_ds')
            from_ds = cond.get('from_ds')
            more_fragments = cond.get('more_fragments')
            retry = cond.get('retry')
            pwr_mgt = cond.get('pwr_mgt')
            more_data = cond.get('more_data')
            protected = cond.get('protected')
            order = cond.get('order')

            return cls(version, type, subtype, to_ds, from_ds, more_fragments, retry, pwr_mgt, more_data, protected,
                       order)

    class QosControl:
        def __init__(self, priority, qos_bit_4, ack_policy, payload_type, second_byte):
            self.priority = priority
            self.qos_bit_4 = qos_bit_4
            self.ack_policy = ack_policy
            self.payload_type = payload_type
            self.second_byte = second_byte
            if qos_bit_4 == 0:
                self.txop_duration_requested = second_byte

        @classmethod
        def from_raw(cls, data):
            # initialize
            priority = None
            qos_bit_4 = None
            ack_policy = None
            payload_type = None
            second_byte = None

            # get values for fields the packet has
            priority = data[0] & 15
            qos_bit_4 = (data[0] >> 4) & 1
            ack_policy = (data[0] >> 5) & 3
            payload_type = data[0] >> 7
            second_byte = data[1]

            return cls(priority, qos_bit_4, ack_policy, payload_type, second_byte)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            priority = cond.get('priority')
            qos_bit_4 = cond.get('qos_bit_4')
            ack_policy = cond.get('ack_policy')
            payload_type = cond.get('payload_type')
            second_byte = cond.get('second_byte')

            return cls(priority, qos_bit_4, ack_policy, payload_type, second_byte)

    class Ccmp:
        def __init__(self, pn, ext_iv, key_id):
            self.pn = pn
            self.ext_iv = ext_iv
            self.key_id = key_id

        @classmethod
        def from_raw(cls, data):
            # initialize
            pn = None
            ext_iv = None
            key_id = None

            # get values for fields the packet has
            pn = bytearray(6)
            pn[0:4] = data[7:3:-1]
            pn[4:6] = data[1::-1]
            pn = int.from_bytes(pn, 'big')
            ext_iv = (data[3] >> 5) & 1
            key_id = data[3] >> 6

            return cls(pn, ext_iv, key_id)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            pn = cond.get('pn')
            ext_iv = cond.get('ext_iv')
            key_id = cond.get('key_id')

            return cls(pn, ext_iv, key_id)
