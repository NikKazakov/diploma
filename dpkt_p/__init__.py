from datetime import datetime
from dpkt import radiotap, ieee80211
import dpkt
import json
import timeit

from extensions import Session, Rule, ipv4_to_bytes, ipv4_to_int, mac_to_bytes, bytes_to_ipv4, bytes_to_mac, COMPARISONS

fields_values_decoder = {
    "arp.sender_ip": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "arp.sender_mac": lambda a: mac_to_bytes(a) if a is not None else b"",
    "arp.target_ip": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "arp.target_mac": lambda a: mac_to_bytes(a) if a is not None else b"",
    "dhcp.client_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.your_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.server_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.gateway_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.client_mac": lambda a: mac_to_bytes(a) if a is not None else b"",
    "dhcp.flags.broadcast": lambda a: a << 15 if a is not None else 0,
    "dhcp.options.subnet_mask": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "dhcp.options.router": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "dhcp.options.domain_name_server": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "dhcp.options.host_name": lambda a: a.encode("utf-8") if a is not None else b"",
    "dhcp.options.broadcast_address": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "dhcp.options.requested_ip_address": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "dhcp.options.server_identifier": lambda a: ipv4_to_bytes(a) if a is not None else b"",
    "ipv4.destination": lambda a: ipv4_to_bytes(a) if a is not None else b""
}


fields_names_decoder = {
    "arp.hardware_type":  "arp.hrd",
    "arp.protocol_type": "arp.pro",
    "arp.hardware_size": "arp.hln",
    "arp.protocol_size": "arp.pln",
    "arp.opcode": "arp.op",
    "arp.sender_mac": "arp.sha",
    "arp.sender_ip": "arp.spa",
    "arp.target_mac": "arp.tha",
    "arp.target_ip": "arp.tpa",
    "dhcp.opcode": "dhcp.op",
    "dhcp.hardware_type": "dhcp.hrd",
    "dhcp.hardware_length": "dhcp.hln",
    "dhcp.hops": "dhcp.hops",
    "dhcp.transaction_id": "dhcp.xid",
    "dhcp.seconds_elapsed": "dhcp.secs",
    "dhcp.flags.broadcast": "dhcp.flags",
    "dhcp.client_ip": "dhcp.ciaddr",
    "dhcp.your_ip": "dhcp.yiaddr",
    "dhcp.server_ip": "dhcp.siaddr",
    "dhcp.gateway_ip": "dhcp.giaddr",
    "dhcp.client_mac": "dhcp.chaddr",
    "dhcp.options.subnet_mask": "dhcp.opts.subnet_mask",
    "dhcp.options.router": "dhcp.opts.router",
    "dhcp.options.domain_name_server": "dhcp.opts.domain_name_server",
    "dhcp.options.host_name": "dhcp.opts.host_name",
    "dhcp.options.broadcast_address": "dhcp.opts.broadcast_address",
    "dhcp.options.requested_ip_address": "dhcp.opts.requested_ip_address",
    "dhcp.options.ip_address_lease_time": "dhcp.opts.ip_address_lease_time",
    "dhcp.options.message_type": "dhcp.opts.message_type",
    "dhcp.options.server_identifier": "dhcp.opts.server_identifier",
    "dot1x_authentication": "ieee8021x",
    "dot1x_authentication.version": "ieee8021x.version",
    "dot1x_authentication.type": "ieee8021x.type",
    "dot1x_authentication.length": "ieee8021x.length",
    "dot1x_authentication.key_descriptor_type":  "ieee8021x.key.key_descriptor_type",
    "dot1x_authentication.key_length": "ieee8021x.key.key_length",
    "dot1x_authentication.replay_counter": "ieee8021x.key.replay_counter",
    "dot1x_authentication.wpa_key_nonce": "ieee8021x.key.wpa_key_nonce",
    "dot1x_authentication.key_iv": "ieee8021x.key.key_iv",
    "dot1x_authentication.wpa_key_rsc": "ieee8021x.key.wpa_key_rsc",
    "dot1x_authentication.wpa_key_id": "ieee8021x.key.wpa_key_id",
    "dot1x_authentication.wpa_key_mic": "ieee8021x.key.wpa_key_mic",
    "dot1x_authentication.wpa_key_data_length": "ieee8021x.key.wpa_key_data_length",
    "dot1x_authentication.wpa_key_data": "ieee8021x.key.wpa_key_data",
    "dot1x_authentication.key_information.key_descriptor_version": "ieee8021x.key.key_descriptor_version",
    "dot1x_authentication.key_information.key_type": "ieee8021x.key.key_type",
    "dot1x_authentication.key_information.key_index": "ieee8021x.key.key_index",
    "dot1x_authentication.key_information.install": "ieee8021x.key.install",
    "dot1x_authentication.key_information.key_ack": "ieee8021x.key.key_ack",
    "dot1x_authentication.key_information.key_mic": "ieee8021x.key.key_mic",
    "dot1x_authentication.key_information.secure": "ieee8021x.key.secure",
    "dot1x_authentication.key_information.error": "ieee8021x.key.error",
    "dot1x_authentication.key_information.request": "ieee8021x.key.request",
    "dot1x_authentication.key_information.encrypted_key_data": "ieee8021x.key.encrypted_key_data",
    "dot1x_authentication.key_information.smk_message": "ieee8021x.key.smk_message",
    "dot11_header": "ieee80211",
    "dot11_header.type": "ieee80211.type",
    "dot11_management": "ieee80211.mgmt",
    "ipv4": "ip",
    "ipv4.destination": "ip.dst",
    "ipv4.ihl": "ip.hl",
}


def do(path, rules):
    for rule in rules:
        for cond in rule.conditions:
            cond.val = fields_values_decoder.get(cond.pth, lambda a: a)(cond.val)
            cond.pth = fields_names_decoder.get(cond.pth, cond.pth)
    s = Session(path)
    start = timeit.default_timer()
    for pkt in s:
        pkt = Packet(*pkt)
        for rule in rules:
            rule_matched = True
            for cond in rule.conditions:
                obj = pkt
                for step in cond.pth.split("."):
                    obj = getattr(obj, step, None)
                if (a := cond.act) in COMPARISONS:
                    condition_matched = COMPARISONS[a](obj, cond.val)
                else:
                    print(f"WARNING: unknown condition in rule {rule.name}: {cond}")
                    condition_matched = False
                if not condition_matched:
                    rule_matched = False
                    break
            if rule_matched:
                rule.do(pkt)
    return timeit.default_timer() - start


class Packet:
    __slots__ = "time", "protos", "ll_type", "radiotap", "ieee80211", "llc", "ip", "tcp", "arp", "udp", "ieee8021x", "eap", "dhcp"

    def __init__(self, ll_type, time, data):
        self.time = time
        self.protos = []
        try:
            ll_types = {
                105: ieee80211.IEEE80211,
                127: radiotap.Radiotap,

            }
            if ll_type not in ll_types:
                print(f"WARNING: unknown ll_type {ll_type}")
                return
            data = ll_types[ll_type](data)
            while True:
                name = data.__class__.__name__.lower()
                if name in self.__slots__:
                    setattr(self, name, data)
                    self.protos.append(name)
                if hasattr(data, "data") and not isinstance(data.data, bytes):
                    data = data.data
                else:
                    break
        except dpkt.dpkt.NeedData:
            #print(f"MALFORMED at {datetime.fromtimestamp(time)}")
            pass

    def summary(self):
        summ = f"[{datetime.fromtimestamp(self.time)}] | "
        for proto in self.protos:
            if proto == "radiotap":
                if self.radiotap.channel_present:
                    if self.radiotap.channel.flags >> 8 & 1:
                        summ += "5 GHz "
                    elif self.radiotap.channel.flags >> 7 & 1:
                        summ += "2.4 GHz "
                summ += f"ch {calc_channel_number(self.radiotap.channel.freq)} "
                if self.radiotap.ant_sig_present:
                    summ += f"{self.radiotap.ant_sig.db} dbm "
                summ += "| "
            elif proto == "ieee80211":
                t = self.ieee80211.type
                s = self.ieee80211.subtype
                if t == 0:
                    summ += f"{ieee80211_m_info[s]} " \
                            f"{bytes_to_mac(self.ieee80211.mgmt.src)} -> " \
                            f"{bytes_to_mac(self.ieee80211.mgmt.dst)} | "
                elif t == 1:
                    if s in (12, 13):
                        summ += f"{ieee80211_c_info[s]} -> " \
                                f"{bytes_to_mac(getattr(self.ieee80211, ieee80211_c_dec[s]).dst)} | "
                    elif s in (8, 9, 10, 11, 14):
                        summ += f"{ieee80211_c_info[s]} " \
                                f"{bytes_to_mac(getattr(self.ieee80211, ieee80211_c_dec[s]).src)} -> " \
                                f"{bytes_to_mac(getattr(self.ieee80211, ieee80211_c_dec[s]).dst)} | "
                    else:
                        summ += f"{ieee80211_c_info[s]} " \
                                f"WARNING: no parser created for type {t} subtype {s} | "
                elif t == 2:
                    summ += f"{ieee80211_d_info[s]} " \
                            f"{bytes_to_mac(self.ieee80211.data_frame.src)} -> " \
                            f"{bytes_to_mac(self.ieee80211.data_frame.dst)} | "
                else:
                    summ += f"{ieee80211_info[t][s]} " \
                            f"WARNING: no parser created for type {t} subtype {s} | "
            elif proto == "ip":
                if "tcp" in self.protos:
                    summ += f"TCP {bytes_to_ipv4(self.ip.src)}:{self.tcp.sport} -> " \
                            f"{bytes_to_ipv4(self.ip.dst)}:{self.tcp.dport} | "
                else:
                    summ += f"{bytes_to_ipv4(self.ip.src)} -> " \
                            f"{bytes_to_ipv4(self.ip.dst)} | "
        return summ.rstrip("| ")


ieee80211_c_dec = {8: "bar", 9: "back", 10: "ps_poll", 11: "rts", 12: "cts", 13: "ack", 14: "cf_end"},
ieee80211_m_info = {0b0000: "Association Request",
                    0b0001: "Association Response",
                    0b0010: "Reassociation Request",
                    0b0011: "Reassociation Response",
                    0b0100: "Probe Request",
                    0b0101: "Probe Response",
                    0b0110: "Timing Advertisement",
                    0b0111: "RESERVED",
                    0b1000: "Beacon",
                    0b1001: "ATIM",
                    0b1010: "Disassociation",
                    0b1011: "Authentication",
                    0b1100: "Deauthentication",
                    0b1101: "Action",
                    0b1110: "Action No Ack",
                    0b1111: "RESERVED"}
ieee80211_c_info = {0b0000: "RESERVED",
                    0b0001: "RESERVED",
                    0b0010: "Trigger",
                    0b0011: "INVALID",
                    0b0100: "Beamforming Report Poll",
                    0b0101: "VHT/HE NDP Announcement",
                    0b0110: "Control Frame Extension",
                    0b0111: "Control Wrapper",
                    0b1000: "Block Ack Request",
                    0b1001: "Block Ack",
                    0b1010: "PS-Poll",
                    0b1011: "RTS",
                    0b1100: "CTS",
                    0b1101: "ACK",
                    0b1110: "CF-End",
                    0b1111: "CF-End + CF-ACK"}
ieee80211_d_info = {0b0000: "Data",
                    0b0001: "Data + CF-ACK",
                    0b0010: "Data + CF-Poll",
                    0b0011: "Data + CF-ACK + CF-Poll",
                    0b0100: "Null (no data)",
                    0b0101: "CF-ACK (no data)",
                    0b0110: "CF-Poll (no data)",
                    0b0111: "CF-ACK + CF-Poll (no data)",
                    0b1000: "QoS Data",
                    0b1001: "QoS Data + CF-ACK",
                    0b1010: "QoS Data + CF-Poll",
                    0b1011: "QoS Data + CF-ACK + CF-Poll",
                    0b1100: "QoS Null (no data)",
                    0b1101: "RESERVED",
                    0b1110: "QoS CF-Poll (no data)",
                    0b1111: "QoS CF-ACK + CF-Poll (no data)"}
ieee80211_info = {0b00: ieee80211_m_info,
                  0b01: ieee80211_c_info,
                  0b10: ieee80211_d_info,
                  0b11: {0b0000: "DMG Beacon",
                         0b0001: "RESERVED",
                         0b0010: "RESERVED",
                         0b0011: "RESERVED",
                         0b0100: "RESERVED",
                         0b0101: "RESERVED",
                         0b0110: "RESERVED",
                         0b0111: "RESERVED",
                         0b1000: "RESERVED",
                         0b1001: "RESERVED",
                         0b1010: "RESERVED",
                         0b1011: "RESERVED",
                         0b1100: "RESERVED",
                         0b1101: "RESERVED",
                         0b1110: "RESERVED",
                         0b1111: "RESERVED"}
                  }


def calc_channel_number(freq):
    if 2412 <= freq <= 2472:
        return int((freq - 2) / 5 - 481)
    elif freq == 2484:
        return 14
    else:
        return int(freq / 5 - 1000)