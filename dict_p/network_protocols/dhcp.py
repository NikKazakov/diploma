from struct import unpack
from extensions import flatten_tuple


def dhcp(data: bytes) -> (list, tuple):
    if len(data) < 236:
        return [], ('MALFORMED', f"DHCP requires at least 236 bytes, got {len(data)}")

    t = unpack('!BBBBIH2sIIII6s10s64s128s', data[:236])
    r = [('opcode', t[0]),
         ('hardware_type', t[1]),
         ('hardware_length', t[2]),
         ('hops', t[3]),
         ('transaction_id', t[4]),
         ('seconds_elapsed', t[5]),
         ('client_ip', t[7]),
         ('your_ip', t[8]),
         ('server_ip', t[9]),
         ('gateway_ip', t[10]),
         ('client_mac', t[11]),
         ('client_padding', t[12]),
         ('server_host_name', t[13]),
         ('boot_file', t[14])]
    r = flatten_tuple(r, _flags(t[6]), 'flags')

    data = data[236:]

    if data:
        r.append(('magic_cookie', magic_cookie := unpack('!4s', data[:4])[0]))
        if magic_cookie == b'\x63\x82\x53\x63':  # Magic number identifies that DHCP (not BOOTP) options follow
            r = flatten_tuple(r, _options(data[4:]), 'options')

    return r, ('UNKNOWN', b'')


def summary(par: dict):
    inf = {1: 'Discover', 2: "Offer", 3: "Request", 5: "ACK"}
    message = 'DHCP'
    if mt := par.get('dhcp.options.message_type'):
        try:
            message += f' {inf[mt]}'
        except KeyError:
            print(f'No description created for DHCP message type {mt}')
    message += f" Transaction ID {par['dhcp.transaction_id']}"
    return message


def _flags(data: bytes) -> list:
    return [('broadcast', data[0] >> 7),
            ('reserved', (data[0] & 127) << 8 | data[1])]


def _options(data: bytes) -> list:
    r = []
    dns_count = 0
    while data:
        option = unpack('!B', data[:1])[0]

        if option == 255:
            break
        else:
            length = unpack('!B', data[1:2])[0]
            option_body = unpack(f'!{length}s', data[2:length + 2])[0]
            if option == 1:
                r.append(('subnet_mask', int.from_bytes(option_body, 'big')))
            elif option == 3:
                r.append(('router', int.from_bytes(option_body, 'big')))
            elif option == 6:
                if dns_count == 0:
                    r.append(('domain_name_server', int.from_bytes(option_body[:4], 'big')))
                    dns_count += 2
                else:
                    r.append((f'domain_name_server_{dns_count}', int.from_bytes(option_body[:4], 'big')))
                    dns_count += 1
            elif option == 12:
                r.append(('host_name', option_body))
            elif option == 28:
                r.append(('broadcast_address', int.from_bytes(option_body, 'big')))
            elif option == 50:
                r.append(('requested_ip_address', int.from_bytes(option_body, 'big')))
            elif option == 51:
                r.append(('ip_address_lease_time', int.from_bytes(option_body, 'big')))
            elif option == 53:
                r.append(('message_type', int.from_bytes(option_body, 'big')))
            elif option == 54:
                r.append(('server_identifier', int.from_bytes(option_body, 'big')))
            elif option == 55:
                r = flatten_tuple(r, _request_list(option_body), 'request_list')
            elif option == 58:
                r.append(('renewal_time', int.from_bytes(option_body, 'big')))
            elif option == 59:
                r.append(('rebinding_time', int.from_bytes(option_body, 'big')))
            elif option == 60:
                r.append(('vendor_class_identifier', option_body))
            elif option == 61:
                r = flatten_tuple(r, _client_identifier(option_body), 'client_identifier')
            elif option == 81:
                r = flatten_tuple(r, _client_fully_qualified_domain_name(option_body), 'client_fully_qualified_domain_name')
            data = data[length + 2:]
    return r


def _request_list(data: bytes) -> list:
    return [('items', data)]


def _client_identifier(data: bytes) -> list:
    t = unpack('!B6s', data[:7])
    return [('hardware_type', t[0]),
            ('client_mac_address', t[1])]


def _client_fully_qualified_domain_name(data: bytes) -> list:
    t = unpack('!sBB', data[:3])
    return flatten_tuple([('a_rr_result', t[1]),
                          ('ptr_rr_result', t[2]),
                          ('client_name', data[3:])],
                         _cfqdn_flags(t[0]), 'flags')


def _cfqdn_flags(data: bytes) -> list:
    return [('server_ddns', data[0] >> 3 & 1),
            ('encoding', data[0] >> 2 & 1),
            ('server_overrides', data[0] >> 1 & 1),
            ('server', data[0] & 1)]