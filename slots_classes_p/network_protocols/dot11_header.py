import struct
import extensions

from .dot11_management import Dot11Management
from .llc import Llc


class Dot11Header:
    __slots__ = 'frame_control', 'duration', 'receiver', 'transmitter', 'destination', 'sequence_number', \
                'fragment_number', 'address_4',  'qos_control', 'ccmp', 'type_subtype', 'ds', 'source', 'bssid', \
                'sta_address', 'payload'
    name = 'dot11_header'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, duration, receiver, transmitter, destination, sequence_number, fragment_number, address_4,
                 frame_control, qos_control, ccmp, payload=None):
        self.frame_control = frame_control
        self.duration = duration
        self.receiver = receiver
        self.transmitter = transmitter
        self.destination = destination
        self.sequence_number = sequence_number
        self.fragment_number = fragment_number
        self.address_4 = address_4
        self.qos_control = qos_control
        self.ccmp = ccmp

        self.type_subtype = frame_control.type << 4 | frame_control.subtype
        self.ds = frame_control.from_ds << 1 | frame_control.to_ds

        if self.ds == 0:
            self.source = transmitter
            self.bssid = destination
            self.sta_address = None
            self.destination = receiver
        elif self.ds == 1:
            self.source = transmitter
            self.bssid = receiver
            self.sta_address = transmitter
        elif self.ds == 2:
            self.source = destination
            self.bssid = transmitter
            self.sta_address = receiver
            self.destination = receiver
        elif self.ds == 3:
            self.source = address_4
            self.bssid = None
            self.sta_address = None

        self.payload = payload

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

        if hasattr(self, 'destination'):
            if hasattr(self, 'source'):
                return f"{inf[t][s]} {self.source} -> {self.destination}"
            return f"{inf[t][s]} {self.destination}"
        return False

    @classmethod
    def from_raw(cls, data):
        if len(data) < 10:
            return extensions.MalformedPacketException(f".11 requires at least 10 bytes, got {len(data)}")

        # get values for fields the packet has
        frame_control, duration, receiver = struct.unpack('!2sH6s', data[:10])
        frame_control = FrameControl.from_raw(frame_control)
        receiver = int.from_bytes(receiver, 'big')
        transmitter = None
        destination = None
        sequence_number = None
        fragment_number = None
        address_4 = None
        qos_control = None
        ccmp = None

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
                print(f'Exception in dot11_header.py: type: {frame_control.type} subtype: {frame_control.subtype}')
            transmitter = int.from_bytes(transmitter, 'big')
            destination = int.from_bytes(destination, 'big')
            sequence_number = sequence_fragment >> 4
            fragment_number = sequence_fragment & 15
            if frame_control.to_ds and frame_control.from_ds:
                address_4 = int.from_bytes(struct.unpack('!6s', data[24:30])[0], 'big')
                last = 30
            else:
                last = 24

        header = cls(duration, receiver, transmitter, destination, sequence_number, fragment_number, address_4,
                     frame_control, qos_control, ccmp)

        if frame_control.type == 0:
            header.payload = Dot11Management.from_raw(data, frame_control.subtype)
        elif frame_control.type == 2 and frame_control.subtype in (0, 8):
            if frame_control.subtype == 8:
                header.qos_control = QosControl.from_raw(struct.unpack('!2s', data[last:last + 2])[0])
                last += 2
            if frame_control.protected:
                header.ccmp = Ccmp.from_raw(struct.unpack('<8s', data[last:last + 8])[0])
                last += 8
            else:
                if frame_control.subtype == 0 or (frame_control.subtype == 8 and header.qos_control.payload_type == 0):
                    header.payload = Llc.from_raw(data[last:])
                else:
                    header.payload = data[last:]
            # that's where we decrypt

        return header


class FrameControl:
    __slots__ = 'version', 'type', 'subtype', 'to_ds', 'from_ds', 'more_fragments', 'retry', 'pwr_mgt', 'more_data',\
                'protected', 'order'

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


class QosControl:
    __slots__ = 'priority', 'qos_bit_4', 'ack_policy', 'payload_type', 'second_byte', 'txop_duration_requested'
    
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
        priority = data[0] & 15
        qos_bit_4 = (data[0] >> 4) & 1
        ack_policy = (data[0] >> 5) & 3
        payload_type = data[0] >> 7
        second_byte = data[1]

        return cls(priority, qos_bit_4, ack_policy, payload_type, second_byte)


class Ccmp:
    __slots__ = 'pn', 'ext_iv', 'key_id'
    
    def __init__(self, pn, ext_iv, key_id):
        self.pn = pn
        self.ext_iv = ext_iv
        self.key_id = key_id

    @classmethod
    def from_raw(cls, data):
        pn = bytearray(6)
        pn[0:4] = data[7:3:-1]
        pn[4:6] = data[1::-1]
        pn = int.from_bytes(pn, 'big')
        ext_iv = (data[3] >> 5) & 1
        key_id = data[3] >> 6

        return cls(pn, ext_iv, key_id)
