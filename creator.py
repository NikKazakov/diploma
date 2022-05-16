import json

def create_rules(n):
    a = [
        ("ANY", 'radiotap', 'y', None, 50000),

        ("arp.hw.type", 'arp.hardware_type', '==', 1, 10954),
        ("arp.proto.type", 'arp.protocol_type', '==', 0x0800, 10954),
        ("arp.hw.size", 'arp.hardware_size', '==', 6, 10954),
        ("arp.proto.size", 'arp.protocol_size', '==', 4, 10954),
        ("arp.opcode", 'arp.opcode', '==', 1, 10865),
        ("arp.src.hw_mac", 'arp.sender_mac', '==', 'a8:f9:4b:ac:86:00', 10754),
        ("arp.src.proto_ipv4", 'arp.sender_ip', '==', '100.117.64.2', 10754),
        ("arp.dst.hw_mac", 'arp.target_mac', '!=', '00:00:00:00:00:00', 89),
        ("arp.dst.proto_ipv4", 'arp.target_ip', '==', '100.117.78.17', 6),

        ("dhcp.type", 'dhcp.opcode', '==', 2, 115),
        ("dhcp.hw.type", 'dhcp.hardware_type', '==', 0x01, 151),
        ("dhcp.hw.len", 'dhcp.hardware_length', '==', 6, 151),
        ("dhcp.hops", 'dhcp.hops', '!=', 0, 5),
        ("dhcp.id", 'dhcp.transaction_id', '==', 0x57c1abaf, 8),
        ("dhcp.secs", 'dhcp.seconds_elapsed', '>', 2, 17),
        ("dhcp.flags.bc", 'dhcp.flags.broadcast', '==', 1, 2),
        ("dhcp.ip.client", 'dhcp.client_ip', '!=', '0.0.0.0', 13),
        ("dhcp.ip.your", 'dhcp.your_ip', '!=', '0.0.0.0', 100),
        ("dhcp.ip.server", 'dhcp.server_ip', '==', '100.127.6.39', 3),
        ("dhcp.ip.relay", 'dhcp.gateway_ip', '==', '100.117.64.2', 5),
        ("dhcp.hw.mac_addr", 'dhcp.client_mac', '!=', '2c:78:0e:a1:5e:12', 148),
        ("dhcp.option.subnet_mask", 'dhcp.options.subnet_mask', '==', '255.255.252.0', 97),
        ("dhcp.option.router", 'dhcp.options.router', '==', '100.96.211.254', 40),
        ("dhcp.option.domain_name_server", 'dhcp.options.domain_name_server', '!=', '10.1.2.11', 69),
        ("dhcp.option.hostname", 'dhcp.options.host_name', 'y', None, 35),
        ("dhcp.option.broadcast_address", 'dhcp.options.broadcast_address', 'y', None, 0),
        ("dhcp.option.requested_ip_address", 'dhcp.options.requested_ip_address', '!=', '100.68.209.226', 9),
        ("dhcp.option.ip_address_lease_time", 'dhcp.options.ip_address_lease_time', '>', 300, 5),
        ("dhcp.option.dhcp", 'dhcp.options.message_type', '==', 2, 15),
        ("dhcp.option.dhcp_server_id", 'dhcp.options.server_identifier', '==', '1.1.1.1', 118),

        ("eapol.version", 'dot1x_authentication.version', '==', 2, 29),
        ("eapol.type", 'dot1x_authentication.type', '==', 3, 290),
        ("eapol.len", 'dot1x_authentication.length', '>', 117, 24),
        ("eapol.keydes.type", 'dot1x_authentication.key_descriptor_type', '==', 2, 256),
        ("eapol.keydes.key_len", 'dot1x_authentication.key_length', '>=', 16, 70),
        ("eapol.keydes.replay_counter", 'dot1x_authentication.replay_counter', '!=', 0, 289),
        ("wlan_rsna_eapol.keydes.nonce", 'dot1x_authentication.wpa_key_nonce', 'y', None, 290),
        ("eapol.keydes.key_iv", 'dot1x_authentication.key_iv', 'n', None, 0),
        ("wlan_rsna_eapol.keydes.rsc", 'dot1x_authentication.wpa_key_rsc', 'y', None, 290),
        ("wlan_rsna_eapol.keydes.id", 'dot1x_authentication.wpa_key_id', 'y', None, 290),
        ("wlan_rsna_eapol.keydes.mic", 'dot1x_authentication.wpa_key_mic', 'y', None, 290),
        ("wlan_rsna_eapol.keydes.data_len", 'dot1x_authentication.wpa_key_data_length', '==', 0, 38),
        ("wlan_rsna_eapol.keydes.data", 'dot1x_authentication.wpa_key_data', 'y', None, 252),
        (
        "wlan_rsna_eapol.keydes.key_info.keydes_version", 'dot1x_authentication.key_information.key_descriptor_version',
        '==', 2, 256),
        ("wlan_rsna_eapol.keydes.key_info.key_type", 'dot1x_authentication.key_information.key_type', '==', 1, 290),
        ("wlan_rsna_eapol.keydes.key_info.key_index", 'dot1x_authentication.key_information.key_index', '==', 0, 290),
        ("wlan_rsna_eapol.keydes.key_info.install", 'dot1x_authentication.key_information.install', '==', 0, 280),
        ("wlan_rsna_eapol.keydes.key_info.key_ack", 'dot1x_authentication.key_information.key_ack', '==', 1, 48),
        ("wlan_rsna_eapol.keydes.key_info.key_mic", 'dot1x_authentication.key_information.key_mic', '==', 1, 252),
        ("wlan_rsna_eapol.keydes.key_info.secure", 'dot1x_authentication.key_information.secure', '==', 1, 1),
        ("wlan_rsna_eapol.keydes.key_info.error", 'dot1x_authentication.key_information.error', '==', 0, 290),
        ("wlan_rsna_eapol.keydes.key_info.request", 'dot1x_authentication.key_information.request', '==', 0, 290),
        (
        "wlan_rsna_eapol.keydes.key_info.encrypted_key_data", 'dot1x_authentication.key_information.encrypted_key_data',
        '==', 0, 289),
        ("wlan_rsna_eapol.keydes.key_info.smk_message", 'dot1x_authentication.key_information.smk_message', '==', 0,
         290),

        ("wlan.fc.version", 'dot11_header.frame_control.version', '==', 0, 10000),
        ("wlan.fc.subtype", 'dot11_header.frame_control.subtype', '==', 8, 4845),
        ("wlan.fc.type", 'dot11_header.frame_control.type', '==', 0, 7024),
        ("wlan.fc.ds", 'dot11_header.frame_control.to_ds', '==', 1, 1068),
        ("wlan.fc.ds", 'dot11_header.frame_control.from_ds', '==', 1, 461),
        ("wlan.fc.frag", 'dot11_header.frame_control.more_fragments', '==', 0, 10000),
        ("wlan.fc.retry", 'dot11_header.frame_control.retry', '==', 1, 1428),
        ("wlan.fc.pwrmgt", 'dot11_header.frame_control.pwr_mgt', '==', 1, 63),
        ("wlan.fc.moredata", 'dot11_header.frame_control.more_data', '==', 1, 223),
        ("wlan.fc.protected", 'dot11_header.frame_control.protected', '==', 1, 451),
        ("wlan.fc.order", 'dot11_header.frame_control.order', '==', 1, 56),
        ("wlan.ra", 'dot11_header.receiver', 'y', None, 10000),
        ("wlan.ta", 'dot11_header.transmitter', 'y', None, 10000),
        ("wlan.da", 'dot11_header.destination', 'y', None, 10000),
        ("wlan.sa", 'dot11_header.source', 'y', None, 10000),
        ("wlan.bssid", 'dot11_header.bssid', 'y', None, 10000),
        ("wlan.staa", 'dot11_header.sta_address', 'y', None, 1509),
        ("wlan.seq", 'dot11_header.sequence_number', '==', 1294, 3),
        ("wlan.frag", 'dot11_header.fragment_number', '==', 0, 7682),
        ("wlan.duration", 'dot11_header.duration', 'y', None, 7206),

        ("idk", "ipv4.version", 'y', None, 0),
        ("idk", "ipv4.ihl", 'y', None, 0),
        ("idk", "ipv4.dscp", 'y', None, 0),
        ("idk", "ipv4.ecn", 'y', None, 0),
        ("idk", "ipv4.total_length", 'y', None, 0),
        ("idk", "ipv4.identification", 'y', None, 0),
        ("idk", "ipv4.flags", 'y', None, 0),
        ("idk", "ipv4.fragment_offset", 'y', None, 0),
        ("idk", "ipv4.ttl", 'y', None, 0),
        ("idk", "ipv4.protocol", 'y', None, 0),
        ("idk", "ipv4.header_checksum", 'y', None, 0),
        ("idk", "ipv4.source", 'y', None, 0),
        ("idk", "ipv4.destination", 'y', None, 0),

        ("idk", "udp.source_port", 'y', None, 0),
        ("idk", "udp.destination_port", 'y', None, 0),
        ("idk", "udp.length", 'y', None, 0),
        ("idk", "udp.checksum", 'y', None, 0),

        ("idk", "llc.dsap", 'y', None, 0),
        ("idk", "llc.ssap", 'y', None, 0),
        ("idk", "llc.control_field", 'y', None, 0),
        ("idk", "llc.organization_code", 'y', None, 0),
        ("idk", "llc.type", 'y', None, 0),

        ("idk", "eap.code", 'y', None, 0),
        ("idk", "eap.id", 'y', None, 0),
        ("idk", "eap.length", 'y', None, 0),
    ]

    r = []
    while len(a) < n:
        a.extend(a)
    a = a[:n]
    for name, pth, act, val, target in a:
        #print(f'"{pth}"')
        r.append({'name': name,
                  'conditions': [{
                      'pth': pth,
                      'act': act,
                      'val': val
                  }],
                  'actions': [{
                      'act': 'count',
                      'obj': None
                  }],
                  'target': target})
    print(len(r))
    with open('rules.json', 'w') as f:
        json.dump(r, f, indent=4)


if __name__ == '__main__':
    create_rules(1)