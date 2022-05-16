import struct
import extensions

from .eap import Eap


class Dot1xAuthentication:
    __slots__ = 'version', 'type', 'length', 'key_descriptor_type', 'key_length', 'replay_counter', 'wpa_key_nonce',\
                'key_iv', 'wpa_key_rsc', 'wpa_key_id', 'wpa_key_mic', 'wpa_key_data_length', 'key_information', \
                'wpa_key_data', 'payload'
    name = 'dot1x_authentication'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, version, type, length, key_descriptor_type, key_length, replay_counter, wpa_key_nonce, key_iv, wpa_key_rsc, wpa_key_id, wpa_key_mic, wpa_key_data_length, key_information, wpa_key_data, payload=None):
        self.version = version
        self.type = type
        self.length = length
        self.key_descriptor_type = key_descriptor_type
        self.key_length = key_length
        self.replay_counter = replay_counter
        self.wpa_key_nonce = wpa_key_nonce
        self.key_iv = key_iv
        self.wpa_key_rsc = wpa_key_rsc
        self.wpa_key_id = wpa_key_id
        self.wpa_key_mic = wpa_key_mic
        self.wpa_key_data_length = wpa_key_data_length
        self.key_information = key_information
        self.wpa_key_data = wpa_key_data
        
        self.payload = payload

    def summary(self):
        if self.type == 3:
            return 'EAPOL RSN Key'
        return False

    @classmethod
    def from_raw(cls, data):
        key_descriptor_type = None
        key_length = None
        replay_counter = None
        wpa_key_nonce = None
        key_iv = None
        wpa_key_rsc = None
        wpa_key_id = None
        wpa_key_mic = None
        wpa_key_data_length = None
        key_information = None
        wpa_key_data = None

        if len(data) < 4:
            return extensions.MalformedPacketException(f"1x_auth requires at least 4 bytes, got {len(data)}")

        version, type, length = struct.unpack('!BBH', data[:4])
        data = data[4:length + 4]

        if type == 0:  # EAP packet
            payload = Eap.from_raw(data)

        elif type == 3:  # key
            key_descriptor_type, key_information, key_length, replay_counter = struct.unpack('!B2sHQ', data[:13])
            key_information = KeyInformation.from_raw(key_information)
            data = data[13:]
            wpa_key_nonce, key_iv, wpa_key_rsc, wpa_key_id, wpa_key_mic, wpa_key_data_length = struct.unpack(
                '!32s16s8s8s16sH', data[:82])
            data = data[82:]
            if wpa_key_data_length:
                wpa_key_data = WpaKeyData.from_raw(data[:wpa_key_data_length])
            payload = data[wpa_key_data_length:]
         
        else:
            payload = extensions.MalformedPacketException(f"WARNING: got 1x packet with unknown yet type: {type}")
            payload.name = 'WARNING'

        return cls(version, type, length, key_descriptor_type, key_length, replay_counter, wpa_key_nonce, key_iv,
                   wpa_key_rsc, wpa_key_id, wpa_key_mic, wpa_key_data_length, key_information, wpa_key_data, payload)


class KeyInformation:
    __slots__ = 'key_descriptor_version', 'key_type', 'key_index', 'install', 'key_ack', 'key_mic', 'secure', 'error', \
                'request', 'encrypted_key_data', 'smk_message'

    def __init__(self, key_descriptor_version, key_type, key_index, install, key_ack, key_mic, secure, error, request,
                 encrypted_key_data, smk_message):
        self.key_descriptor_version = key_descriptor_version
        self.key_type = key_type
        self.key_index = key_index
        self.install = install
        self.key_ack = key_ack
        self.key_mic = key_mic
        self.secure = secure
        self.error = error
        self.request = request
        self.encrypted_key_data = encrypted_key_data
        self.smk_message = smk_message
        
    @classmethod
    def from_raw(cls, data):
        key_descriptor_version = data[1] & 7
        key_type = (data[1] >> 3) & 1
        key_index = (data[1] >> 4) & 3
        install = (data[1] >> 6) & 1
        key_ack = data[1] >> 7
        key_mic = data[0] & 1
        secure = (data[0] >> 1) & 1
        error = (data[0] >> 2) & 1
        request = (data[0] >> 3) & 1
        encrypted_key_data = (data[0] >> 4) & 1
        smk_message = (data[0] >> 5) & 1

        return cls(key_descriptor_version, key_type, key_index, install, key_ack, key_mic, secure, error, request, encrypted_key_data, smk_message)


class WpaKeyData:
    __slots__ = 'data'
    
    def __init__(self, data):
        self.data = data
        
    @classmethod
    def from_raw(cls, data):
        return cls(data)

