import json
from datetime import datetime
import timeit

from extensions import Session, Rule, COMPARISONS, ipv4_to_int, mac_to_int, mac_to_bytes

from .network_protocols import *
from dump_writer import DumpWriter

fields_values_decoder = {
    'arp.sender_ip': lambda a: ipv4_to_int(a) if a is not None else b'',
    'arp.sender_mac': lambda a: mac_to_int(a) if a is not None else b'',
    'arp.target_ip': lambda a: ipv4_to_int(a) if a is not None else b'',
    'arp.target_mac': lambda a: mac_to_int(a) if a is not None else b'',
    "dhcp.client_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.your_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.server_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.gateway_ip": lambda a: ipv4_to_int(a) if a is not None else 0,
    "dhcp.client_mac": lambda a: mac_to_bytes(a) if a is not None else b'',
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
        pkt = Packet(pkt)
        for rule in rules:
            rule_matched = True
            for cond in rule.conditions:
                obj = True if cond.pth in pkt.protos else pkt.fields.get(cond.pth)
                if (a := cond.act) in COMPARISONS:
                    condition_matched = COMPARISONS[a](obj, cond.val)
                else:
                    print(f'WARNING: unknown condition in rule {rule.name}: {cond}')
                    condition_matched = False
                if not condition_matched:
                    rule_matched = False
            if rule_matched:
                rule.add(pkt)
    return timeit.default_timer() - start


class Packet:
    __slots__ = 'fields', 'protos', 'll_type', 'time', 'data'

    def get(self, field, default=None):
        return self.fields.get(field, default)

    def get_time(self):
        return datetime.fromtimestamp(float(self.time))

    def summary(self) -> str:
        words = [f"[{self.get_time()}]", ]
        for proto in self.protos:
            if word := PROTOS_SUMMARY[proto](self.fields):
                words.append(word)
        return " | ".join(words)

    def __init__(self, pkt):
        self.time = None
        self.fields = {}
        self.protos = []
        self.ll_type, self.time, self.data = pkt
        payload = (LL_TYPES[self.ll_type], self.data)

        while payload:
            proto, data, *extra = payload
            temp, payload, *extra = PROTOS_CONSTRUCTOR[proto](data, *extra)

            if payload[0] in ('MALFORMED','TO_DECRYPT','UNKNOWN'):
                payload = None

            for k, v in temp:
                self.fields[f"{proto}.{k}"] = v
            self.protos.append(proto)
