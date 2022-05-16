import struct
import extensions


class Dhcp:
    name = 'dhcp'

    # Fields that come from raw are necessary
    # Payload can be None cause from_dict can't set it
    # Then come the unnecessary/additional fields that exist for better naming
    def __init__(self, opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, client_ip,
                 your_ip, server_ip, gateway_ip, client_mac, server_host_name, boot_file, flags, options, payload=None):
        self.opcode = opcode  # 0x01 -- from client to server (BOOTREQUEST), 0x02 -- from server to client (BOOTREPLY)
        self.hardware_type = hardware_type
        self.hardware_length = hardware_length
        self.hops = hops
        self.transaction_id = transaction_id
        self.seconds_elapsed = seconds_elapsed
        self.client_ip = client_ip
        self.your_ip = your_ip
        self.server_ip = server_ip
        self.gateway_ip = gateway_ip
        self.client_mac = client_mac
        self.server_host_name = server_host_name
        self.boot_file = boot_file
        self.flags = flags
        self.options = options

        self.payload = payload

    def get_all_fields(self, all=False, repr=False):
        # if all is set, returns all fields
        # if repr is set, returns certain fields in human-readable format
        # returns non-Null (rule.Any, bytes or int) fields by default
        keys = ['opcode',
                'hardware_type',
                'hardware_length',
                'hops',
                'transaction_id',
                'seconds_elapsed',
                'client_ip',
                'your_ip',
                'server_ip',
                'gateway_ip',
                'client_mac',
                'server_host_name',
                'boot_file',
                'flags.broadcast',
                'flags.reserved',
                'options.subnet_mask',
                'options.router',
                'options.domain_name_server',
                'options.host_name',
                'options.broadcast_address',
                'options.requested_ip_address',
                'options.ip_address_lease_time',
                'options.message_type',
                'options.server_identifier',
                'options.request_list.items',
                'options.renewal_time',
                'options.rebinding_time',
                'options.vendor_class_identifier',
                'options.client_identifier.hardware_type',
                'options.client_identifier.client_mac_address',
                'options.client_fully_qualified_domain_name.flags.server_ddns',
                'options.client_fully_qualified_domain_name.flags.encoding',
                'options.client_fully_qualified_domain_name.flags.server_overrides',
                'options.client_fully_qualified_domain_name.flags.server',
                'options.client_fully_qualified_domain_name.a_rr_result',
                'options.client_fully_qualified_domain_name.ptr_rr_result',
                'options.client_fully_qualified_domain_name.client_name',
                ]
        values = [self.opcode,
                  self.hardware_type,
                  self.hardware_length,
                  self.hops,
                  self.transaction_id,
                  self.seconds_elapsed,
                  self.client_ip,
                  self.your_ip,
                  self.server_ip,
                  self.gateway_ip,
                  self.client_mac,
                  self.server_host_name,
                  self.boot_file,
                  self.flags.broadcast,
                  self.flags.reserved,
                  self.options.subnet_mask,
                  self.options.router,
                  self.options.domain_name_server,
                  self.options.host_name,
                  self.options.broadcast_address,
                  self.options.requested_ip_address,
                  self.options.ip_address_lease_time,
                  self.options.message_type,
                  self.options.server_identifier,
                  self.options.request_list.items,
                  self.options.renewal_time,
                  self.options.rebinding_time,
                  self.options.vendor_class_identifier,
                  self.options.client_identifier.hardware_type,
                  self.options.client_identifier.client_mac_address,
                  self.options.client_fully_qualified_domain_name.flags.server_ddns,
                  self.options.client_fully_qualified_domain_name.flags.encoding,
                  self.options.client_fully_qualified_domain_name.flags.server_overrides,
                  self.options.client_fully_qualified_domain_name.flags.server,
                  self.options.client_fully_qualified_domain_name.a_rr_result,
                  self.options.client_fully_qualified_domain_name.ptr_rr_result,
                  self.options.client_fully_qualified_domain_name.client_name,
                  ]
        if all:
            ret = {k: v for (k, v) in zip(keys, values)}
        else:
            ret = {k: v for (k, v) in zip(keys, values) if v is not None}
        if repr:
            if 'client_ip' in ret:
                ret['client_ip'] = extensions.int_to_ipv4(self.client_ip)
            if 'your_ip' in ret:
                ret['your_ip'] = extensions.int_to_ipv4(self.your_ip)
            if 'server_ip' in ret:
                ret['server_ip'] = extensions.int_to_ipv4(self.server_ip)
            if 'gateway_ip' in ret:
                ret['gateway_ip'] = extensions.int_to_ipv4(self.gateway_ip)
            if 'client_mac' in ret:
                ret['client_mac'] = extensions.int_to_mac(self.client_mac)
            if 'options.subnet_mask' in ret:
                ret['options.subnet_mask'] = extensions.int_to_ipv4(self.options.subnet_mask)
            if 'options.router' in ret:
                ret['options.router'] = extensions.int_to_ipv4(self.options.router)
            if 'options.host_name' in ret:
                ret['options.host_name'] = str(self.options.host_name)[2:-1]
            if 'options.broadcast_address' in ret:
                ret['options.broadcast_address'] = extensions.int_to_ipv4(self.options.broadcast_address)
            if 'options.requested_ip_address' in ret:
                ret['options.requested_ip_address'] = extensions.int_to_ipv4(self.options.requested_ip_address)
            if 'options.server_identifier' in ret:
                ret['options.server_identifier'] = extensions.int_to_ipv4(self.options.server_identifier)
            if 'options.vendor_class_identifier' in ret:
                ret['options.vendor_class_identifier'] = str(self.options.vendor_class_identifier)[2:-1]
            if 'options.client_identifier.client_mac_address' in ret:
                ret['options.client_identifier.client_mac_address'] = \
                    extensions.int_to_mac(self.options.client_identifier.client_mac_address)
            if 'options.client_fully_qualified_domain_name.client_name' in ret:
                ret['options.client_fully_qualified_domain_name.client_name'] = \
                    str(self.options.client_fully_qualified_domain_name.client_name)[2:-1]
        return ret

    # handle alternative/additional field names
    @staticmethod
    def get_full_names(cond):
        n_cond = {}
        for field in cond:
            n_cond[field] = cond[field]
        return n_cond

    def summary(self):
        inf = {1: 'Discover', 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK"}
        message = 'DHCP'
        if self.options.message_type:
            try:
                message += f' {inf[self.options.message_type]}'
            except KeyError:
                print(f'No description created for DHCP message type {self.options.message_type}')
        message += f' Transaction ID {self.transaction_id}'
        return message

    @classmethod
    def from_raw(cls, data):
        # initialize
        opcode = None
        hardware_type = None
        hardware_length = None
        hops = None
        transaction_id = None
        seconds_elapsed = None
        client_ip = None
        your_ip = None
        server_ip = None
        gateway_ip = None
        client_mac = None
        server_host_name = None
        boot_file = None
        flags = cls.Flags.from_dict({})
        options = cls.Options.from_dict({})

        if len(data) < 236:
            return extensions.MalformedPacketException(f"DHCP requires at least 236 bytes, got {len(data)}")

        opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, flags, client_ip, your_ip, \
        server_ip, gateway_ip, client_mac, client_padding, server_host_name, boot_file = \
            struct.unpack('!BBBBIH2sIIII6s10s64s128s', data[:236])

        flags = cls.Flags.from_raw(flags)
        client_mac = int.from_bytes(client_mac, 'big')

        data = data[236:]
        payload = b''

        if data:
            magic_cookie = struct.unpack('!4s', data[:4])[0]
            if magic_cookie == b'\x63\x82\x53\x63':  # Magic number identifies that DHCP (not BOOTP) options follow
                options = cls.Options.from_raw(data[4:])

        return cls(opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, client_ip, your_ip,
                   server_ip, gateway_ip, client_mac, server_host_name, boot_file, flags, options, payload)

    @classmethod
    def from_dict(cls, cond):
        # get full names for each field
        cond = cls.get_full_names(cond)

        # get simple fields user can access
        opcode = cond.get('opcode')
        hardware_type = cond.get('hardware_type')
        hardware_length = cond.get('hardware_length')
        hops = cond.get('hops')
        transaction_id = cond.get('transaction_id')
        seconds_elapsed = cond.get('seconds_elapsed')
        client_ip = cond.get('client_ip')
        your_ip = cond.get('your_ip')
        server_ip = cond.get('server_ip')
        gateway_ip = cond.get('gateway_ip')
        client_mac = cond.get('client_mac')
        server_host_name = cond.get('server_host_name')
        boot_file = cond.get('boot_file')

        # initialise complex/flag fields the user can access
        flags = {}
        options = {}

        # collect complex fields into dictionaries
        for field in cond:
            if field.startswith('flags.'):
                flags[field.split('.', 1)[1]] = cond[field]
            if field.startswith('options.'):
                options[field.split('.', 1)[1]] = cond[field]

        # and initialise them
        flags = cls.Flags.from_dict(flags)
        options = cls.Options.from_dict(options)

        return cls(opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, client_ip, your_ip,
                   server_ip, gateway_ip, client_mac, server_host_name, boot_file, flags, options)

    class Flags:
        def __init__(self, broadcast, reserved):
            self.broadcast = broadcast
            self.reserved = reserved

        @classmethod
        def from_raw(cls, data):
            # initialize
            broadcast = None
            reserved = None

            broadcast = data[0] >> 7
            reserved = (data[0] & 127) << 8 | data[1]

            return cls(broadcast, reserved)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            broadcast = cond.get('broadcast')
            reserved = cond.get('reserved')

            return cls(broadcast, reserved)

    class Options:
        def __init__(self, subnet_mask, router, domain_name_server, host_name, broadcast_address, requested_ip_address,
                     ip_address_lease_time, message_type, server_identifier, renewal_time, rebinding_time,
                     vendor_class_identifier, request_list, client_identifier, client_fully_qualified_domain_name, additional_dns):
            self.subnet_mask = subnet_mask
            self.router = router
            self.domain_name_server = domain_name_server
            self.host_name = host_name
            self.broadcast_address = broadcast_address
            self.requested_ip_address = requested_ip_address
            self.ip_address_lease_time = ip_address_lease_time
            self.message_type = message_type
            self.server_identifier = server_identifier
            self.renewal_time = renewal_time
            self.rebinding_time = rebinding_time
            self.vendor_class_identifier = vendor_class_identifier
            self.request_list = request_list
            self.client_identifier = client_identifier
            self.client_fully_qualified_domain_name = client_fully_qualified_domain_name
            self.additional_dns = additional_dns

        @classmethod
        def from_raw(cls, data):
            # initialize
            subnet_mask = None
            router = None
            domain_name_server = None
            host_name = None
            broadcast_address = None
            requested_ip_address = None
            ip_address_lease_time = None
            message_type = None
            server_identifier = None
            renewal_time = None
            rebinding_time = None
            vendor_class_identifier = None
            request_list = cls.RequestList.from_dict({})
            client_identifier = cls.ClientIdentifier.from_dict({})
            client_fully_qualified_domain_name = cls.ClientFullyQualifiedDomainName.from_dict({})
            additional_dns = []

            while data:
                option = struct.unpack('!B', data[:1])[0]

                if option == 255:
                    break
                else:
                    length = struct.unpack('!B', data[1:2])[0]
                    option_body = struct.unpack(f'!{length}s', data[2:length + 2])[0]
                    if option == 1:
                        subnet_mask = int.from_bytes(option_body, 'big')
                    elif option == 3:
                        router = int.from_bytes(option_body, 'big')
                    elif option == 6:
                        if domain_name_server is None:
                            domain_name_server = int.from_bytes(option_body[:4], 'big')
                        else:
                            additional_dns.append(int.from_bytes(option_body[:4], 'big'))
                    elif option == 12:
                        host_name = option_body
                    elif option == 28:
                        broadcast_address = int.from_bytes(option_body, 'big')
                    elif option == 50:
                        requested_ip_address = int.from_bytes(option_body, 'big')
                    elif option == 51:
                        ip_address_lease_time = int.from_bytes(option_body, 'big')
                    elif option == 53:
                        message_type = int.from_bytes(option_body, 'big')
                    elif option == 54:
                        server_identifier = int.from_bytes(option_body, 'big')
                    elif option == 55:
                        request_list = cls.RequestList.from_raw(option_body)
                    elif option == 58:
                        renewal_time = int.from_bytes(option_body, 'big')
                    elif option == 59:
                        rebinding_time = int.from_bytes(option_body, 'big')
                    elif option == 60:
                        vendor_class_identifier = option_body
                    elif option == 61:
                        client_identifier = cls.ClientIdentifier.from_raw(option_body)
                    elif option == 81:
                        client_fully_qualified_domain_name = cls.ClientFullyQualifiedDomainName.from_raw(option_body)
                    data = data[length + 2:]

            return cls(subnet_mask, router, domain_name_server, host_name, broadcast_address, requested_ip_address, ip_address_lease_time, message_type, server_identifier, renewal_time, rebinding_time, vendor_class_identifier, request_list, client_identifier, client_fully_qualified_domain_name,  additional_dns)

        @classmethod
        def from_dict(cls, cond):
            # get simple fields user can access
            subnet_mask = cond.get('subnet_mask')
            router = cond.get('router')
            domain_name_server = cond.get('domain_name_server')
            host_name = cond.get('host_name')
            broadcast_address = cond.get('broadcast_address')
            requested_ip_address = cond.get('requested_ip_address')
            ip_address_lease_time = cond.get('ip_address_lease_time')
            message_type = cond.get('message_type')
            server_identifier = cond.get('server_identifier')
            renewal_time = cond.get('renewal_time')
            rebinding_time = cond.get('rebinding_time')
            vendor_class_identifier = cond.get('vendor_class_identifier')
            additional_dns = cond.get('additional_dns')

            # initialise complex/flag fields the user can access
            request_list = {}
            client_identifier = {}
            client_fully_qualified_domain_name = {}

            # collect complex fields into dictionaries
            for field in cond:
                pass
                if field.startswith('request_list.'):
                    request_list[field.split('.', 1)[1]] = cond[field]
                if field.startswith('client_identifier.'):
                    client_identifier[field.split('.', 1)[1]] = cond[field]
                if field.startswith('client_fully_qualified_domain_name.'):
                    client_fully_qualified_domain_name[field.split('.', 1)[1]] = cond[field]

            # and initialise them
            request_list = cls.RequestList.from_dict(request_list)
            client_identifier = cls.ClientIdentifier.from_dict(client_identifier)
            client_fully_qualified_domain_name = cls.ClientFullyQualifiedDomainName.from_dict(
                client_fully_qualified_domain_name)

            return cls(subnet_mask, router, domain_name_server, host_name, broadcast_address, requested_ip_address,
                       ip_address_lease_time, message_type, server_identifier, renewal_time, rebinding_time,
                       vendor_class_identifier, request_list, client_identifier, client_fully_qualified_domain_name, additional_dns)

        class ClientIdentifier:
            def __init__(self, hardware_type, client_mac_address):
                self.hardware_type = hardware_type
                self.client_mac_address = client_mac_address

            @classmethod
            def from_raw(cls, data):
                # initialize
                hardware_type = None
                client_mac_address = None

                hardware_type, client_mac_address = struct.unpack('!B6s', data[:7])
                client_mac_address = int.from_bytes(client_mac_address, 'big')

                return cls(hardware_type, client_mac_address)

            @classmethod
            def from_dict(cls, cond):
                # get simple fields user can access
                hardware_type = cond.get('hardware_type')
                client_mac_address = cond.get('client_mac_address')

                return cls(hardware_type, client_mac_address)

        class RequestList:
            def __init__(self, items):
                self.items = items

            @classmethod
            def from_raw(cls, data):
                # initialize
                items = None

                items = data

                return cls(items)

            @classmethod
            def from_dict(cls, cond):
                # get simple fields user can access
                items = cond.get('items')

                return cls(items)

        class ClientFullyQualifiedDomainName:
            def __init__(self, a_rr_result, ptr_rr_result, client_name, flags):
                self.a_rr_result = a_rr_result
                self.ptr_rr_result = ptr_rr_result
                self.client_name = client_name
                self.flags = flags

            @classmethod
            def from_raw(cls, data):
                # initialize
                a_rr_result = None
                ptr_rr_result = None
                client_name = None
                flags = cls.Flags.from_dict({})

                # get values for fields the packet has
                flags, a_rr_result, ptr_rr_result = struct.unpack('!sBB', data[:3])
                flags = cls.Flags.from_raw(flags)
                client_name = data[3:]

                return cls(a_rr_result, ptr_rr_result, client_name, flags)

            @classmethod
            def from_dict(cls, cond):
                # get simple fields user can access
                a_rr_result = cond.get('a_rr_result')
                ptr_rr_result = cond.get('ptr_rr_result')
                client_name = cond.get('client_name')

                # initialise complex/flag fields the user can access
                flags = {}

                # collect complex fields into dictionaries
                for field in cond:
                    pass
                    if field.startswith('flags.'):
                        flags[field.split('.', 1)[1]] = cond[field]

                # and initialise them
                flags = cls.Flags.from_dict(flags)

                return cls(a_rr_result, ptr_rr_result, client_name, flags)

            class Flags:
                def __init__(self, server_ddns, encoding, server_overrides, server):
                    self.server_ddns = server_ddns
                    self.encoding = encoding
                    self.server_overrides = server_overrides
                    self.server = server

                @classmethod
                def from_raw(cls, data):
                    # initialize
                    server_ddns = None
                    encoding = None
                    server_overrides = None
                    server = None

                    # get values for fields the packet has
                    server_ddns = (data[0] >> 3) & 1
                    encoding = (data[0] >> 2) & 1
                    server_overrides = (data[0] >> 1) & 1
                    server = data[0] & 1

                    return cls(server_ddns, encoding, server_overrides, server)

                @classmethod
                def from_dict(cls, cond):
                    # get simple fields user can access
                    server_ddns = cond.get('server_ddns')
                    encoding = cond.get('encoding')
                    server_overrides = cond.get('server_overrides')
                    server = cond.get('server')

                    return cls(server_ddns, encoding, server_overrides, server)