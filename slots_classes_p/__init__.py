from datetime import datetime
import json
import timeit

from extensions import Session, Rule, COMPARISONS, ipv4_to_int, mac_to_int

from .network_protocols import *


fields_values_decoder = {
    'arp.sender_ip': lambda a: ipv4_to_int(a) if a is not None else b'',
    'arp.sender_mac': lambda a: mac_to_int(a) if a is not None else b'',
    'arp.target_ip': lambda a: ipv4_to_int(a) if a is not None else b'',
    'arp.target_mac': lambda a: mac_to_int(a) if a is not None else b'',
    "dhcp.client_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.your_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.server_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.gateway_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.client_mac": lambda a: mac_to_int(a) if a is not None else b'',
    "dhcp.options.subnet_mask": lambda a: ipv4_to_int(a) if a is not None else b'',
    "dhcp.options.router": lambda a: ipv4_to_int(a) if a is not None else b'',
    "dhcp.options.domain_name_server": lambda a: ipv4_to_int(a) if a is not None else b'',
    "dhcp.options.host_name": lambda a: a.encode('utf-8') if a is not None else b'',
    "dhcp.options.broadcast_address": lambda a: ipv4_to_int(a) if a is not None else b'',
    "dhcp.options.requested_ip_address": lambda a: ipv4_to_int(a) if a is not None else b'',
    "dhcp.options.server_identifier": lambda a: ipv4_to_int(a) if a is not None else b'',
    "ipv4.destination": lambda a: ipv4_to_int(a) if a is not None else b''
}


def do(path, rules):
    for rule in rules:
        for cond in rule.conditions:
            cond.val = fields_values_decoder.get(cond.pth, lambda a: a)(cond.val)
    s = Session(path)
    start = timeit.default_timer()
    for pkt in s:
        pkt = Packet.from_raw(*pkt)
        for rule in rules:
            rule_matched = True
            for cond in rule.conditions:
                obj = pkt.p
                for step in cond.pth.split('.'):
                    obj = getattr(obj, step, None)
                if (a := cond.act) in COMPARISONS:
                    condition_matched = COMPARISONS[a](obj, cond.val)
                else:
                    print(f'WARNING: unknown condition in rule {rule.name}: {cond}')
                    condition_matched = False
                if not condition_matched:
                    rule_matched = False
                    break
            if rule_matched:
                rule.do(pkt)
    return timeit.default_timer() - start


class P:
    __slots__ = 'radiotap', 'dot11_header', 'ether', 'dot11_management', 'llc', 'arp', 'dot1x_authentication',  'ipv4',\
                'eap', 'udp', 'dhcp', 'WARNING', 'MALFORMED'


class Packet:
    __slots__ = 'p', 'protos', 'll_type', 'time', 'data'

    def __init__(self, protos, ll_type, time, data):
        self.p = P()
        self.protos = protos
        self.ll_type = ll_type
        self.time = time
        self.data = data

    def summary(self) -> str:
        summary = f"[{datetime.fromtimestamp(self.time)}] | "
        for proto in self.protos:
            if l_sum := getattr(self.p, proto).summary():
                summary += f"{l_sum} | "
        summary.rstrip('| ')
        return summary

    @classmethod
    def from_raw(cls, ll_type, time, data):
        error = None
        p_pkt = None
        # those are starting layers of a packet
        if ll_type == 1:  # ether
            p_pkt = Ether.from_raw(data)
        elif ll_type == 105:  # dot11_header
            p_pkt = Dot11Header.from_raw(data)
        elif ll_type == 127:  # radiotap
            p_pkt = Radiotap.from_raw(data)

        # extract layers from subsequent payloads
        layers = [(p_pkt.name, p_pkt), ]
        while p_pkt.payload is not None and not isinstance(p_pkt.payload, bytes):
            layers.append((p_pkt.payload.name, p_pkt.payload))
            if p_pkt.payload.name == 'MALFORMED':
                error = 'malformed'
                break
            elif p_pkt.payload.name == 'WARNING':
                error = 'warning'
                p_pkt.payload.payload = None
            p_pkt = p_pkt.payload
        # remove now useless payload from each layer
        for i in layers:
            i[1].payload = None

        ret = Packet(tuple(i[0] for i in layers), ll_type, time, data)
        for k, v in layers:
            setattr(ret.p, k, v)

        if error == 'warning':
            print(ret.summary())

        return ret
