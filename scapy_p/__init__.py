import json
import timeit
from scapy.all import rdpcap

from extensions import Rule, COMPARISONS, mac_to_bytes

fields_values_decoder = {
    "dhcp.client_mac": lambda a: mac_to_bytes(a) + b'\x00'*10,
    "dhcp.flags.broadcast": lambda a: a << 15 if a is not None else 0,
}

fields_names_decoder = {
    "arp": "ARP",
    "arp.hardware_type":  "ARP.hwtype",
    "arp.protocol_type": "ARP.ptype",
    "arp.hardware_size": "ARP.hwlen",
    "arp.protocol_size": "ARP.plen",
    "arp.opcode": "ARP.op",
    "arp.sender_mac": "ARP.hwsrc",
    "arp.sender_ip": "ARP.psrc",
    "arp.target_mac": "ARP.hwdst",
    "arp.target_ip": "ARP.pdst",
    "dhcp.opcode": "BOOTP.op",
    "dhcp.hardware_type": "BOOTP.htype",
    "dhcp.hardware_length": "BOOTP.hlen",
    "dhcp.hops": "BOOTP.hops",
    "dhcp.transaction_id": "BOOTP.xid",
    "dhcp.seconds_elapsed": "BOOTP.secs",
    "dhcp.flags.broadcast": "BOOTP.flags",
    "dhcp.client_ip": "BOOTP.ciaddr",
    "dhcp.your_ip": "BOOTP.yiaddr",
    "dhcp.server_ip": "BOOTP.siaddr",
    "dhcp.gateway_ip": "BOOTP.giaddr",
    "dhcp.client_mac": "BOOTP.chaddr",
    "dot11_header": "Dot11",
    "dot11_header.type": "Dot11.type",
    "dot1x_authentication": "EAPOL",
    "dot1x_authentication.version": "EAPOL.version",
    "dot1x_authentication.type": "EAPOL.type",
    "dot1x_authentication.length": "EAPOL.len",
    "eap": "EAP",
    "ipv4": "IP",
    "ipv4.destination": "IP.dst",
    "ipv4.ihl": "IP.ihl",
    "llc": "LLC",
    "radiotap": "RadioTap",
    "udp": "UDP",
}


def do(path, report):
    with open('rules.json') as f:
        rules = [Rule(i) for i in json.load(f)]
    for rule in rules:
        for cond in rule.conditions:
            cond.val = fields_values_decoder.get(cond.pth, lambda a: a)(cond.val)
            cond.pth = fields_names_decoder.get(cond.pth, cond.pth)
    start = timeit.default_timer()
    s = rdpcap(path)
    for pkt in s:
        for rule in rules:
            rule_matched = True
            for cond in rule.conditions:
                if '.' in cond.pth:
                    proto, field = cond.pth.split('.', 1)
                    if pkt.haslayer(proto):
                        obj = pkt[proto]
                        while '.' in field:
                            f, field = field.split('.', 1)
                            obj = getattr(obj, f)
                        obj = getattr(obj, field)
                    else:
                        obj = None
                else:
                    if pkt.haslayer(cond.pth):
                        obj = pkt[cond.pth]
                    else:
                        try:
                            obj = getattr(pkt, cond.pth)
                        except AttributeError:
                            obj = None
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
    print(f'Scapy: {timeit.default_timer() - start}')
    for rule in rules:
        for i in rule.report(*report):
            print(i, end='')
