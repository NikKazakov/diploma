import struct
import extensions


class Dot11Management:
    name = 'dot11_management'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, fixed_parameters, tagged_parameters, payload=None):
        self.fixed_parameters = fixed_parameters
        self.tagged_parameters = tagged_parameters
        
        self.payload = payload

    def get_all_fields(self, all=False,  repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['fixed_parameters.capabilities_information.ess_capabilities',
                'fixed_parameters.capabilities_information.ibss_status',
                'fixed_parameters.capabilities_information.cfp_participation_capabilities',
                'fixed_parameters.capabilities_information.privacy',
                'fixed_parameters.capabilities_information.short_preamble',
                'fixed_parameters.capabilities_information.pbcc',
                'fixed_parameters.capabilities_information.channel_agility',
                'fixed_parameters.capabilities_information.spectrum_management',
                'fixed_parameters.capabilities_information.short_slot_time',
                'fixed_parameters.capabilities_information.automatic_power_save_delivery',
                'fixed_parameters.capabilities_information.radio_measurement',
                'fixed_parameters.capabilities_information.dsss_ofdm',
                'fixed_parameters.capabilities_information.delayed_block_ack',
                'fixed_parameters.capabilities_information.immediate_block_ack',
                'fixed_parameters.listen_interval',
                'fixed_parameters.current_ap',
                'fixed_parameters.status_code',
                'fixed_parameters.association_id',
                'fixed_parameters.timestamp',
                'fixed_parameters.beacon_interval',
                'fixed_parameters.authentication_algorithm',
                'fixed_parameters.authentication_seq',
                'fixed_parameters.action.category_code',
                'fixed_parameters.action.action_code',
                'tagged_parameters.ssid',
                'tagged_parameters.supported_rates',
                'tagged_parameters.traffic_indication_map',
                'tagged_parameters.country_information',
                'tagged_parameters.power_constraint',
                'tagged_parameters.tpc_report_transmit_power',
                'tagged_parameters.ht_capabilities',
                'tagged_parameters.ht_information',
                'tagged_parameters.vht_capabilities',
                'tagged_parameters.vht_operation',
                'tagged_parameters.rsn_information',
                'tagged_parameters.vendor_specific',
                'tagged_parameters.extended_capabilities',
                ]
        values = [self.fixed_parameters.capabilities_information.ess_capabilities,
                  self.fixed_parameters.capabilities_information.ibss_status,
                  self.fixed_parameters.capabilities_information.cfp_participation_capabilities,
                  self.fixed_parameters.capabilities_information.privacy,
                  self.fixed_parameters.capabilities_information.short_preamble,
                  self.fixed_parameters.capabilities_information.pbcc,
                  self.fixed_parameters.capabilities_information.channel_agility,
                  self.fixed_parameters.capabilities_information.spectrum_management,
                  self.fixed_parameters.capabilities_information.short_slot_time,
                  self.fixed_parameters.capabilities_information.automatic_power_save_delivery,
                  self.fixed_parameters.capabilities_information.radio_measurement,
                  self.fixed_parameters.capabilities_information.dsss_ofdm,
                  self.fixed_parameters.capabilities_information.delayed_block_ack,
                  self.fixed_parameters.capabilities_information.immediate_block_ack,
                  self.fixed_parameters.listen_interval,
                  self.fixed_parameters.current_ap,
                  self.fixed_parameters.status_code,
                  self.fixed_parameters.association_id,
                  self.fixed_parameters.timestamp,
                  self.fixed_parameters.beacon_interval,
                  self.fixed_parameters.authentication_algorithm,
                  self.fixed_parameters.authentication_seq,
                  self.fixed_parameters.action.category_code,
                  self.fixed_parameters.action.action_code,
                  self.tagged_parameters.ssid,
                  self.tagged_parameters.supported_rates,
                  self.tagged_parameters.traffic_indication_map,
                  self.tagged_parameters.country_information,
                  self.tagged_parameters.power_constraint,
                  self.tagged_parameters.tpc_report_transmit_power,
                  self.tagged_parameters.ht_capabilities,
                  self.tagged_parameters.ht_information,
                  self.tagged_parameters.vht_capabilities,
                  self.tagged_parameters.vht_operation,
                  self.tagged_parameters.rsn_information,
                  self.tagged_parameters.vendor_specific,
                  self.tagged_parameters.extended_capabilities,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'fixed_parameters.current_ap' in ret:
                ret['fixed_parameters.current_ap'] = extensions.int_to_mac(ret['fixed_parameters.current_ap'])
            if 'tagged_parameters.ssid' in ret:
                ret['tagged_parameters.ssid'] = str(self.tagged_parameters.ssid)[2:-1]
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            if field.startswith('fixed.'):
                n_cond[f'fixed_parameters.{field[6:]}'] = cond[field]
            elif field.startswith('tagged.'):
                n_cond[f'tagged_parameters.{field[7:]}'] = cond[field]
            elif '.capabilities.' in field:
                n_cond[field.replace('.capabilities.', 'capabilities_information')] = cond[field]
            else:
                n_cond[field] = cond[field]
        return n_cond

    def summary(self):
        ret = ''
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
        fixed_parameters, data = cls.FixedParameters.from_raw(data, subtype)
        tagged_parameters, payload = cls.TaggedParameters.from_raw(data)
        return cls(fixed_parameters, tagged_parameters, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        
        # initialise complex/flag fields the user can access
        fixed_parameters = {}
        tagged_parameters = {}
        
        # collect complex fields into dictionaries
        for field in cond:
            pass
            if field.startswith('fixed_parameters.'):
                fixed_parameters[field.split('.', 1)[1]] = cond[field]
            if field.startswith('tagged_parameters.'):
                tagged_parameters[field.split('.', 1)[1]] = cond[field]
            
        # and initialise them
        fixed_parameters = cls.FixedParameters.from_dict(fixed_parameters)
        tagged_parameters = cls.TaggedParameters.from_dict(tagged_parameters)

        return cls(fixed_parameters, tagged_parameters)

    class FixedParameters:
        def __init__(self, listen_interval, current_ap, status_code, association_id, timestamp, beacon_interval, authentication_algorithm, authentication_seq, capabilities_information, action):
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
            capabilities_information = cls.CapabilitiesInformation(None, None, None, None, None, None, None, None, None, None, None, None, None, None)
            action = cls.Action(None, None)
            
            # get values for fields the packet has
            last = 0

            if subtype == 0:  # association request
                capabilities_information, listen_interval = struct.unpack('<2sH', data[:4])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
                last = 4
            elif subtype == 1:  # association response
                capabilities_information, status_code, association_id = struct.unpack('<2sHH', data[:6])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
                association_id = association_id & 16383  # 14 bits
                last = 6
            elif subtype == 2:  # reassociation request
                capabilities_information, listen_interval, current_ap = struct.unpack('<2sH6s', data[:10])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
                current_ap = int.from_bytes(current_ap, 'big')
                last = 10
            elif subtype == 3:  # reassociation response
                capabilities_information, status_code, association_id = struct.unpack('<2sHH', data[:6])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
                association_id = association_id & 16383  # 14 bits
                last = 6
            elif subtype == 4:  # probe request
                pass
            elif subtype == 5:  # probe response
                timestamp, beacon_interval, capabilities_information = struct.unpack('<QH2s', data[:12])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
                last = 12
            elif subtype == 6:
                pass
            elif subtype == 7:
                pass
            elif subtype == 8:  # beacon
                timestamp, beacon_interval, capabilities_information = struct.unpack('<QH2s', data[:12])
                capabilities_information = cls.CapabilitiesInformation.from_raw(capabilities_information)
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
                action, data = cls.Action.from_raw(data)
            elif subtype == 14:
                pass
            else:
                print(f" Frame malformed? Unknown frame subtype: {subtype}.")

            return cls(listen_interval, current_ap, status_code, association_id, timestamp, beacon_interval, authentication_algorithm, authentication_seq, capabilities_information, action), data[last:]

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            listen_interval = cond.get('listen_interval')
            current_ap = cond.get('current_ap')
            status_code = cond.get('status_code')
            association_id = cond.get('association_id')
            timestamp = cond.get('timestamp')
            beacon_interval = cond.get('beacon_interval')
            authentication_algorithm = cond.get('authentication_algorithm')
            authentication_seq = cond.get('authentication_seq')
            
            # initialise complex/flag fields the user can access
            capabilities_information = {}
            action = {}
            
            # collect complex fields into dictionaries
            for field in cond:
                pass
                if field.startswith('capabilities_information.'):
                    capabilities_information[field.split('.', 1)[1]] = cond[field]
                if field.startswith('action.'):
                    action[field.split('.', 1)[1]] = cond[field]
                
            # and initialise them
            capabilities_information = cls.CapabilitiesInformation.from_dict(capabilities_information)
            action = cls.Action.from_dict(action)

            return cls(listen_interval, current_ap, status_code, association_id, timestamp, beacon_interval, authentication_algorithm, authentication_seq, capabilities_information, action)

        class CapabilitiesInformation:
            def __init__(self, ess_capabilities, ibss_status, cfp_participation_capabilities, privacy, short_preamble, pbcc, channel_agility, spectrum_management, short_slot_time, automatic_power_save_delivery, radio_measurement, dsss_ofdm, delayed_block_ack, immediate_block_ack):
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
                # initialize
                ess_capabilities = None
                ibss_status = None
                cfp_participation_capabilities = None
                privacy = None
                short_preamble = None
                pbcc = None
                channel_agility = None
                spectrum_management = None
                short_slot_time = None
                automatic_power_save_delivery = None
                radio_measurement = None
                dsss_ofdm = None
                delayed_block_ack = None
                immediate_block_ack = None
                
                # get values for fields the packet has
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

                return cls(ess_capabilities, ibss_status, cfp_participation_capabilities, privacy, short_preamble, pbcc, channel_agility, spectrum_management, short_slot_time, automatic_power_save_delivery, radio_measurement, dsss_ofdm, delayed_block_ack, immediate_block_ack)

            @classmethod
            def from_dict(cls, cond):
                # get simple fields user can access
                ess_capabilities = cond.get('ess_capabilities')
                ibss_status = cond.get('ibss_status')
                cfp_participation_capabilities = cond.get('cfp_participation_capabilities')
                privacy = cond.get('privacy')
                short_preamble = cond.get('short_preamble')
                pbcc = cond.get('pbcc')
                channel_agility = cond.get('channel_agility')
                spectrum_management = cond.get('spectrum_management')
                short_slot_time = cond.get('short_slot_time')
                automatic_power_save_delivery = cond.get('automatic_power_save_delivery')
                radio_measurement = cond.get('radio_measurement')
                dsss_ofdm = cond.get('dsss_ofdm')
                delayed_block_ack = cond.get('delayed_block_ack')
                immediate_block_ack = cond.get('immediate_block_ack')

                return cls(ess_capabilities, ibss_status, cfp_participation_capabilities, privacy, short_preamble, pbcc, channel_agility, spectrum_management, short_slot_time, automatic_power_save_delivery, radio_measurement, dsss_ofdm, delayed_block_ack, immediate_block_ack)

        class Action:
            def __init__(self, category_code, action_code):
                self.category_code = category_code
                self.action_code = action_code
                
            @classmethod
            def from_raw(cls, data):
                # initialize
                category_code = None
                action_code = None
                
                # get values for fields the packet has
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

            @classmethod
            def from_dict(cls, cond):
                # get simple fields user can access
                category_code = cond.get('category_code')
                action_code = cond.get('action_code')

                return cls(category_code, action_code)

    class TaggedParameters:
        def __init__(self, ssid, supported_rates, traffic_indication_map, country_information, power_constraint, tpc_report_transmit_power, ht_capabilities, ht_information, vht_capabilities, vht_operation, rsn_information, vendor_specific, extended_capabilities):
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
            # initialize
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
            
            # get values for fields the packet has
            tags = {}
            while data:
                try:
                    tag_number, tag_length = struct.unpack('!BB', data[:2])
                    try:
                        tag_value = struct.unpack(f'!{tag_length}s', data[2:tag_length + 2])[0]
                    except struct.error as e:
                        #return extensions.MalformedPacketException(f"Is packet malformed? Couldn't unpack: {e}")
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
                traffic_indication_map = cls.TrafficIndicationMap.from_raw(tags[5][0], tags[5][1])
            if 7 in tags:
                country_information = cls.CountryInformation.from_raw(tags[7][0], tags[7][1])
            if 32 in tags:
                power_constraint = tags[32][1]
            if 35 in tags:
                tpc_report_transmit_power = cls.TPCReportTransmitPower.from_raw(tags[35][0], tags[35][1])
            if 45 in tags:
                ht_capabilities = cls.HTCapabilities.from_raw(tags[45][0], tags[45][1])
            if 48 in tags:
                rsn_information = cls.RSNInformation.from_raw(tags[48][0], tags[48][1])
            if 61 in tags:
                ht_information = cls.HTInformation.from_raw(tags[61][0], tags[61][1])
            if 127 in tags:
                extended_capabilities = cls.ExtendedCapabilities.from_raw(tags[127][0], tags[127][1])
            if 191 in tags:
                vht_capabilities = cls.VHTCapabilities.from_raw(tags[191][0], tags[191][1])
            if 192 in tags:
                vht_operation = cls.VHTOperation.from_raw(tags[192][0], tags[192][1])
            if 221 in tags:
                vendor_specific = cls.VendorSpecific.from_raw(tags[221][0], tags[221][1])

            return cls(ssid, supported_rates, traffic_indication_map, country_information, power_constraint, tpc_report_transmit_power, ht_capabilities, ht_information, vht_capabilities, vht_operation, rsn_information, vendor_specific, extended_capabilities), None

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            ssid = cond.get('ssid')
            supported_rates = cond.get('supported_rates')
            traffic_indication_map = cond.get('traffic_indication_map')
            country_information = cond.get('country_information')
            power_constraint = cond.get('power_constraint')
            tpc_report_transmit_power = cond.get('tpc_report_transmit_power')
            ht_capabilities = cond.get('ht_capabilities')
            ht_information = cond.get('ht_information')
            vht_capabilities = cond.get('vht_capabilities')
            vht_operation = cond.get('vht_operation')
            rsn_information = cond.get('rsn_information')
            vendor_specific = cond.get('vendor_specific')
            extended_capabilities = cond.get('extended_capabilities')


            return cls(ssid, supported_rates, traffic_indication_map, country_information, power_constraint, tpc_report_transmit_power, ht_capabilities, ht_information, vht_capabilities, vht_operation, rsn_information, vendor_specific, extended_capabilities)

        class TrafficIndicationMap:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class CountryInformation:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class TPCReportTransmitPower:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class HTCapabilities:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class RSNInformation:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class HTInformation:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class ExtendedCapabilities:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class VHTCapabilities:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class VHTOperation:
            @classmethod
            def from_raw(cls, length, data):
                return data

        class VendorSpecific:
            @classmethod
            def from_raw(cls, length, data):
                return data
