from datetime import datetime
import json
import timeit
from collections import OrderedDict
from decimal import Decimal

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
                obj = pkt
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
    #for rule in rules:
    #    for i in rule.report(*report):
    #        print(i, end='')


class Packet(OrderedDict):
    ll_type = None
    time = None
    data = None
    p = None

    def set_meta(self, ll_type: int, time: Decimal, p: []):
        self.ll_type = ll_type
        self.time = time
        self.p = p

    def get_attributes(self, repr=False):
        return {name.lower(): value.get_all_fields(repr=repr) for name, value in self.items()}

    def get_time(self):
        # TODO check usages and make everything use Decimal so we don't lose precision
        return float(self.time)

    def summary(self) -> str:
        summary = f"[{datetime.fromtimestamp(self.get_time())}]"
        for name in self.p:
            if l_sum := getattr(self, name).summary():
                summary += f" {l_sum} |"
        summary.rstrip('|')
        return summary

    @classmethod
    def from_raw(cls, ll_type, time, data):
        p_pkt = None
        # those are starting layers of a packet
        if ll_type == 1:  # ether
            p_pkt = Ether.from_raw(data)
        elif ll_type == 105:  # dot11_header
            p_pkt = Dot11Header.from_raw(data)
        if ll_type == 127:  # radiotap
            p_pkt = Radiotap.from_raw(data)

        # extract layers from subsequent payloads
        layers = [(p_pkt.name, p_pkt), ]
        while p_pkt.payload is not None and not isinstance(p_pkt.payload, bytes):
            layers.append((p_pkt.payload.name, p_pkt.payload))
            if p_pkt.payload.name == 'MALFORMED':
                break
            p_pkt = p_pkt.payload

        ret = Packet()
        p = []
        # remove now useless payload from each layer
        for k, v in layers:
            v.payload = None
            setattr(ret, k, v)
            p.append(k)

        ret.set_meta(ll_type, time, p)
        ret.data = data

        return ret

    def __eq__(self, other):
        if self.ll_type == other.ll_type and self.time == other.time and self.data == other.data:
            ret = True
            for name, val in self.items():
                if not val.get_all_fields() == other[name].get_all_fields():
                    ret = False
                    break
            return ret
        return False