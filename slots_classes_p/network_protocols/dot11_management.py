import struct


class Dot11Management:
    __slots__ = 'fixed_parameters', 'tagged_parameters', 'payload'
    name = 'dot11_management'

    def __init__(self, fixed_parameters, tagged_parameters, payload=None):
        self.fixed_parameters = fixed_parameters
        self.tagged_parameters = tagged_parameters
        
        self.payload = payload

    def summary(self):
        ret = ''
        if self.fixed_parameters.action:
            if self.fixed_parameters.action.category_code:
                try:
                    inf = {3: 'Block Ack', 4: 'Public Action', 5: 'Radio Measurement', 10: 'WNM', 127: 'Vendor specific'}
                    ret += f"Category: {inf[self.fixed_parameters.action.category_code]}"
                except KeyError:
                    print(f'No description created for category code {self.fixed_parameters.action.category_code}')
        if self.fixed_parameters.authentication_seq:
            ret += f"Authentication SEQ: {self.fixed_parameters.authentication_seq}"
        if self.tagged_parameters.ssid:
            ret += f"SSID:{str(self.tagged_parameters.ssid)[2:-1]}"
        return ret

    @classmethod
    def from_raw(cls, data, subtype):
        fixed_parameters, data = FixedParameters.from_raw(data, subtype)
        tagged_parameters, payload = TaggedParameters.from_raw(data)
        return cls(fixed_parameters, tagged_parameters, payload)


class FixedParameters:
    __slots__ = 'listen_interval', 'current_ap', 'status_code', 'association_id', 'timestamp', 'beacon_interval', \
                 'authentication_algorithm', 'authentication_seq', 'capabilities_information', 'action'

    def __init__(self, listen_interval, current_ap, status_code, association_id, timestamp, beacon_interval,
                 authentication_algorithm, authentication_seq, capabilities_information, action):
        self.listen_interval = listen_interval
        self.current_ap = current_ap
        self.status_code = status_code
        self.association_id = association_id
        self.timestamp = timestamp
        self.beacon_interval = beacon_interval
        self.authentication_algorithm = authentication_algorithm
        self.authentication_seq = authentication_seq
        self.capabilities_information = capabilities_information
        self.action = action

    @classmethod
    def from_raw(cls, data, subtype):
        # initialize
        listen_interval = None
        current_ap = None
        status_code = None
        association_id = None
        timestamp = None
        beacon_interval = None
        authentication_algorithm = None
        authentication_seq = None
        capabilities_information = None
        action = None

        # get values for fields the packet has
        last = 0

        if subtype == 0:  # association request
            capabilities_information, listen_interval = struct.unpack('<2sH', data[:4])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            last = 4
        elif subtype == 1:  # association response
            capabilities_information, status_code, association_id = struct.unpack('<2sHH', data[:6])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            association_id = association_id & 16383  # 14 bits
            last = 6
        elif subtype == 2:  # reassociation request
            capabilities_information, listen_interval, current_ap = struct.unpack('<2sH6s', data[:10])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            current_ap = int.from_bytes(current_ap, 'big')
            last = 10
        elif subtype == 3:  # reassociation response
            capabilities_information, status_code, association_id = struct.unpack('<2sHH', data[:6])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            association_id = association_id & 16383  # 14 bits
            last = 6
        elif subtype == 4:  # probe request
            pass
        elif subtype == 5:  # probe response
            timestamp, beacon_interval, capabilities_information = struct.unpack('<QH2s', data[:12])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            last = 12
        elif subtype == 6:
            pass
        elif subtype == 7:
            pass
        elif subtype == 8:  # beacon
            timestamp, beacon_interval, capabilities_information = struct.unpack('<QH2s', data[:12])
            capabilities_information = CapabilitiesInformation.from_raw(capabilities_information)
            last = 12
        elif subtype == 9:
            pass
        elif subtype == 10:  # disassociation
            reason_code = struct.unpack('<H', data[:2])[0]
            last = 2
        elif subtype == 11:  # authentication
            authentication_algorithm, authentication_seq, status_code = struct.unpack('<HHH', data[:6])
            last = 6
        elif subtype == 12:  # deauthentication
            reason_code = struct.unpack('<H', data[:2])[0]
            last = 2
        elif subtype == 13:
            action, data = Action.from_raw(data)
        elif subtype == 14:
            pass
        else:
            print(f" Frame malformed? Unknown frame subtype: {subtype}.")

        return cls(listen_interval, current_ap, status_code, association_id, timestamp, beacon_interval,
                   authentication_algorithm, authentication_seq, capabilities_information, action), data[last:]


class CapabilitiesInformation:
    __slots__ = 'ess_capabilities', 'ibss_status', 'cfp_participation_capabilities', 'privacy', 'short_preamble', \
                'pbcc', 'channel_agility', 'spectrum_management', 'short_slot_time', 'automatic_power_save_delivery', \
                'radio_measurement', 'dsss_ofdm', 'delayed_block_ack', 'immediate_block_ack'
    
    def __init__(self, ess_capabilities, ibss_status, cfp_participation_capabilities, privacy, short_preamble, pbcc, 
                 channel_agility, spectrum_management, short_slot_time, automatic_power_save_delivery, radio_measurement, 
                 dsss_ofdm, delayed_block_ack, immediate_block_ack):
        self.ess_capabilities = ess_capabilities
        self.ibss_status = ibss_status
        self.cfp_participation_capabilities = cfp_participation_capabilities
        self.privacy = privacy
        self.short_preamble = short_preamble
        self.pbcc = pbcc
        self.channel_agility = channel_agility
        self.spectrum_management = spectrum_management
        self.short_slot_time = short_slot_time
        self.automatic_power_save_delivery = automatic_power_save_delivery
        self.radio_measurement = radio_measurement
        self.dsss_ofdm = dsss_ofdm
        self.delayed_block_ack = delayed_block_ack
        self.immediate_block_ack = immediate_block_ack
        
    @classmethod
    def from_raw(cls, data):
        ess_capabilities = data[0] & 1
        ibss_status = (data[0] >> 1) & 1
        # this is three separate bits. If something is wrong, its here
        cfp_participation_capabilities = (((data[1] >> 1) & 1) << 2) | (data[0] >> 2) & 3
        privacy = (data[0] >> 4) & 1
        short_preamble = (data[0] >> 5) & 1
        pbcc = (data[0] >> 6) & 1
        channel_agility = data[0] >> 7
        spectrum_management = data[1] & 1
        short_slot_time = (data[1] >> 2) & 1
        automatic_power_save_delivery = (data[1] >> 3) & 1
        radio_measurement = (data[1] >> 4) & 1
        dsss_ofdm = (data[1] >> 5) & 1
        delayed_block_ack = (data[1] >> 6) & 1
        immediate_block_ack = (data[1] >> 7) & 1
    
        return cls(ess_capabilities, ibss_status, cfp_participation_capabilities, privacy, short_preamble, pbcc, 
                   channel_agility, spectrum_management, short_slot_time, automatic_power_save_delivery, 
                   radio_measurement, dsss_ofdm, delayed_block_ack, immediate_block_ack)


class Action:
    __slots__ = 'category_code', 'action_code'

    def __init__(self, category_code, action_code):
        self.category_code = category_code
        self.action_code = action_code

    @classmethod
    def from_raw(cls, data):

        category_code, action_code = struct.unpack('<BB', data[:2])
        data = data[2:]
        if category_code == 3:
            if action_code == 0:
                dialog_token, block_ack_parameters, block_ack_timeout, block_ack_ssc = struct.unpack('<BHHH',
                                                                                                     data[:7])
                data = data[7:]
            elif action_code == 1:
                dialog_token, status_code, block_ack_parameters, block_ack_timeout = struct.unpack('<BHHH',
                                                                                                   data[:7])
                data = data[7:]
            elif action_code == 2:
                delete_block_ack, reason_code = struct.unpack('<HH', data[:4])
                data = data[4:]
            else:
                data = b''
        elif category_code == 5:
            if action_code == 0:
                dialog_token, repetitions = struct.unpack('<BH', data[:3])
                data = data[3:]
            elif action_code == 4:
                dialog_token = struct.unpack('<B', data[:1])[0]
                data = data[1:]
            else:
                data = b''
        elif category_code == 10:
            data = b''
        elif category_code == 127:  # Vendor specific
            data = b''
        else:
            data = b''

        return cls(category_code, action_code), data


class TaggedParameters:
    __slots__ = 'ssid', 'supported_rates', 'traffic_indication_map', 'country_information', 'power_constraint', \
                'tpc_report_transmit_power', 'ht_capabilities', 'ht_information', 'vht_capabilities', 'vht_operation', \
                'rsn_information', 'vendor_specific', 'extended_capabilities'

    def __init__(self, ssid, supported_rates, traffic_indication_map, country_information, power_constraint,
                 tpc_report_transmit_power, ht_capabilities, ht_information, vht_capabilities, vht_operation,
                 rsn_information, vendor_specific, extended_capabilities):
        self.ssid = ssid
        self.supported_rates = supported_rates
        self.traffic_indication_map = traffic_indication_map
        self.country_information = country_information
        self.power_constraint = power_constraint
        self.tpc_report_transmit_power = tpc_report_transmit_power
        self.ht_capabilities = ht_capabilities
        self.ht_information = ht_information
        self.vht_capabilities = vht_capabilities
        self.vht_operation = vht_operation
        self.rsn_information = rsn_information
        self.vendor_specific = vendor_specific
        self.extended_capabilities = extended_capabilities
        
    @classmethod
    def from_raw(cls, data):
        ssid = None
        supported_rates = None
        traffic_indication_map = None
        country_information = None
        power_constraint = None
        tpc_report_transmit_power = None
        ht_capabilities = None
        ht_information = None
        vht_capabilities = None
        vht_operation = None
        rsn_information = None
        vendor_specific = None
        extended_capabilities = None

        tags = {}
        while data:
            try:
                tag_number, tag_length = struct.unpack('!BB', data[:2])
                try:
                    tag_value = struct.unpack(f'!{tag_length}s', data[2:tag_length + 2])[0]
                except struct.error as e:
                    tag_value = struct.unpack(f'!{len(data)}s', data)[0]
            except:
                tag_number = 256
                tag_length = 256
                tag_value = struct.unpack(f'!{len(data)}s', data)[0]
            tags[tag_number] = (tag_length, tag_value)
            # TODO: account for vendor-specific
            data = data[tag_length + 2:]
        if 0 in tags:
            if tags[0][1]:
                ssid = tags[0][1]  # If we have a name
            else:
                ssid = b'Wildcard (Broadcast)'  # If it's hidden
        if 1 in tags:
            supported_rates = tags[1][1]
        if 5 in tags:
            traffic_indication_map = tags[5][1]
        if 7 in tags:
            country_information = tags[7][1]
        if 32 in tags:
            power_constraint = tags[32][1]
        if 35 in tags:
            tpc_report_transmit_power = tags[35][1]
        if 45 in tags:
            ht_capabilities = tags[45][1]
        if 48 in tags:
            rsn_information = tags[48][1]
        if 61 in tags:
            ht_information = tags[61][1]
        if 127 in tags:
            extended_capabilities = tags[127][1]
        if 191 in tags:
            vht_capabilities = tags[191][1]
        if 192 in tags:
            vht_operation = tags[192][1]
        if 221 in tags:
            vendor_specific = tags[221][1]

        return cls(ssid, supported_rates, traffic_indication_map, country_information, power_constraint, tpc_report_transmit_power, ht_capabilities, ht_information, vht_capabilities, vht_operation, rsn_information, vendor_specific, extended_capabilities), None
