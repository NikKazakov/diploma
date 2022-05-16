import struct
import extensions


class Dhcp:
    __slots__ = 'opcode', 'hardware_type', 'hardware_length', 'hops', 'transaction_id', 'seconds_elapsed', 'client_ip',\
                'your_ip', 'server_ip', 'gateway_ip', 'client_mac', 'server_host_name', 'boot_file', 'flags', \
                'options', 'payload'
    name = 'dhcp'

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

    def summary(self):
        inf = {1: 'Discover', 2: "Offer", 3: "Request", 5: "ACK"}
        message = 'DHCP'
        if self.options:
            if self.options.message_type:
                try:
                    message += f' {inf[self.options.message_type]}'
                except KeyError:
                    print(f'No description created for DHCP message type {self.options.message_type}')
        message += f' Transaction ID {self.transaction_id}'
        return message

    @classmethod
    def from_raw(cls, data):
        options = None

        if len(data) < 236:
            return extensions.MalformedPacketException(f"DHCP requires at least 236 bytes, got {len(data)}")

        opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, flags, client_ip, your_ip, \
        server_ip, gateway_ip, client_mac, client_padding, server_host_name, boot_file = \
            struct.unpack('!BBBBIH2sIIII6s10s64s128s', data[:236])

        flags = Flags.from_raw(flags)
        client_mac = int.from_bytes(client_mac, 'big')

        data = data[236:]
        payload = b''

        if data:
            magic_cookie = struct.unpack('!4s', data[:4])[0]
            if magic_cookie == b'\x63\x82\x53\x63':  # Magic number identifies that DHCP (not BOOTP) options follow
                options = Options.from_raw(data[4:])

        return cls(opcode, hardware_type, hardware_length, hops, transaction_id, seconds_elapsed, client_ip, your_ip,
                   server_ip, gateway_ip, client_mac, server_host_name, boot_file, flags, options, payload)


class Flags:
    __slots__ = 'broadcast', 'reserved'

    def __init__(self, broadcast, reserved):
        self.broadcast = broadcast
        self.reserved = reserved

    @classmethod
    def from_raw(cls, data):
        broadcast = data[0] >> 7
        reserved = (data[0] & 127) << 8 | data[1]

        return cls(broadcast, reserved)


class Options:
    __slots__ = 'subnet_mask', 'router', 'domain_name_server', 'host_name', 'broadcast_address', \
                'requested_ip_address', 'ip_address_lease_time', 'message_type', 'server_identifier', 'renewal_time', \
                'rebinding_time', 'vendor_class_identifier', 'request_list', 'client_identifier', \
                'client_fully_qualified_domain_name', 'additional_dns'

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
        request_list = None
        client_identifier = None
        client_fully_qualified_domain_name = None
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
                    request_list = RequestList.from_raw(option_body)
                elif option == 58:
                    renewal_time = int.from_bytes(option_body, 'big')
                elif option == 59:
                    rebinding_time = int.from_bytes(option_body, 'big')
                elif option == 60:
                    vendor_class_identifier = option_body
                elif option == 61:
                    client_identifier = ClientIdentifier.from_raw(option_body)
                elif option == 81:
                    client_fully_qualified_domain_name = ClientFullyQualifiedDomainName.from_raw(option_body)
                data = data[length + 2:]
    
        return cls(subnet_mask, router, domain_name_server, host_name, broadcast_address, requested_ip_address, ip_address_lease_time, message_type, server_identifier, renewal_time, rebinding_time, vendor_class_identifier, request_list, client_identifier, client_fully_qualified_domain_name, additional_dns)


class ClientIdentifier:
    __slots__ = 'hardware_type', 'client_mac_address'
    
    def __init__(self, hardware_type, client_mac_address):
        self.hardware_type = hardware_type
        self.client_mac_address = client_mac_address

    @classmethod
    def from_raw(cls, data):
        hardware_type, client_mac_address = struct.unpack('!B6s', data[:7])
        client_mac_address = int.from_bytes(client_mac_address, 'big')

        return cls(hardware_type, client_mac_address)


class RequestList:
    __slots__ = 'items'
    
    def __init__(self, items):
        self.items = items

    @classmethod
    def from_raw(cls, data):
        return cls(data)


class ClientFullyQualifiedDomainName:
    __slots__ = 'a_rr_result', 'ptr_rr_result', 'client_name', 'flags'
    
    def __init__(self, a_rr_result, ptr_rr_result, client_name, flags):
        self.a_rr_result = a_rr_result
        self.ptr_rr_result = ptr_rr_result
        self.client_name = client_name
        self.flags = flags

    @classmethod
    def from_raw(cls, data):
        flags, a_rr_result, ptr_rr_result = struct.unpack('!sBB', data[:3])
        flags = CFQDNFlags.from_raw(flags)
        client_name = data[3:]

        return cls(a_rr_result, ptr_rr_result, client_name, flags)


class CFQDNFlags:
    __slots__ = 'server_ddns', 'encoding', 'server_overrides', 'server'
    
    def __init__(self, server_ddns, encoding, server_overrides, server):
        self.server_ddns = server_ddns
        self.encoding = encoding
        self.server_overrides = server_overrides
        self.server = server

    @classmethod
    def from_raw(cls, data):
        server_ddns = (data[0] >> 3) & 1
        encoding = (data[0] >> 2) & 1
        server_overrides = (data[0] >> 1) & 1
        server = data[0] & 1

        return cls(server_ddns, encoding, server_overrides, server)
