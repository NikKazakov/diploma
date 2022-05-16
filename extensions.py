import binascii
import pickle
import dpkt
from bisect import bisect_left
from decimal import Decimal

COMPARISONS = {
    '==': lambda a, b: False if a is None else a == b,
    '!=': lambda a, b: False if a is None else a != b,
    '<=': lambda a, b: False if a is None else a <= b,
    '>=': lambda a, b: False if a is None else a >= b,
    '<': lambda a, b: False if a is None else a < b,
    '>': lambda a, b: False if a is None else a > b,
    'y': lambda a, b: a is not None,
    'n': lambda a, b: a is None,
}


class Condition:
    __slots__ = 'pth', 'act', 'val'

    def __init__(self, pth, act, val=None):
        self.pth = pth
        self.act = act
        self.val = val


class Action:
    __slots__ = 'act', 'obj'

    def __init__(self, act, obj):
        self.act = act
        self.obj = obj


class Rule:
    __slots__ = 'name', 'conditions', 'actions', 'target', 'interval', 'timeout', 'counter', 'times', 'last_possible', 'inactive_until'

    def __init__(self, d):
        self.name = d['name']
        self.conditions = [Condition(i.get('pth'), i['act'], i.get('val')) for i in d['conditions']]
        self.actions = [Action(i['act'], i['obj']) for i in d['actions']]
        self.target = d['target']
        self.timeout = d['timeout']
        self.interval = Decimal(d['interval'])
        self.counter = 0
        self.times = []
        self.last_possible = 0
        self.inactive_until = 0

    def add(self, pkt):
        time = pkt.time
        if time > self.inactive_until:
            if time > self.last_possible:
                self.times = self.times[bisect_left(self.times, time-self.interval):]
            self.times.append(time)
            if len(self.times) == self.target:
                self.times = []
                self.inactive_until = time + self.timeout
                self.do(pkt)

    def do(self, pkt):
        for action in self.actions:
            if action.act == 'print':
                print(f'Rule {self.name} ringed at {pkt.get_time()}')
                if action.obj == 'summary':
                    print(pkt.summary())
                elif action.obj == 'show':
                    print(pkt.show())
            elif action.act == 'count':
                self.counter += 1

    def report(self, show_name=False, show_conditions=False, show_actions=False, show_counter=False, show_match_target=True):
        r = []
        if show_name:
            r.append(self.name)
        if show_counter:
            r.append(f'\t{self.counter}\n')
        if show_conditions:
            r.append('  conditions:\n')
            for cond in self.conditions:
                r.append(f'    {cond.pth} {cond.act} {cond.val}\n')
        if show_actions:
            r.append('  actions:\n')
            for act in self.actions:
                r.append(f'    {act.act} {act.obj}\n')
        if show_match_target:
            if self.counter != self.target:
                r.append(f'  {self.name} did not match: expected {self.target}, got {self.counter}\n')
        return r


class Session:
    def __init__(self, path):
        self.pcap = dpkt.pcap.Reader(open(path, 'rb'))
        self.ll_type = self.pcap.datalink()
        self.__iter = iter(self)

    def __next__(self):
        return next(self.__iter)

    def __iter__(self):
        for i in self.pcap:
            yield self.ll_type, *i


def flatten_tuple(r, t, name):
    for k, v in t:
        r.append((f'{name}.{k}', v))
    return r


def construct_msg(cmd, obj):
    obj = pickle.dumps(obj)
    x = len(obj)
    size = int.to_bytes(x, (x.bit_length() + 7) // 8, byteorder='big')
    x = len(size)
    ssize = int.to_bytes(x, (x.bit_length() + 7) // 8, byteorder='big')
    return cmd + ssize + size + obj

"""
Used to specify ipv4 addresses as networks, with low and high addresses
Currently unused because isn't finished
Plans: override __eq__ method to check if other is a single address and if it's fits into network
Maybe check built-in first???
"""
class ipv4_address:
    def __init__(self, addr, mask):
        if not isinstance(addr, int):
            addr = ipv4_to_int(addr)
        if not isinstance(mask, int):
            mask = ipv4_to_int(mask)
        self.low = addr & mask
        self.high = addr | (4294967295 - mask)

    @classmethod
    def from_collapsed_mask(cls, s):
        s = s.split('/')
        mask = int('0b' + '1' * (n := int(s[1])) + '0' * (32 - n), 2)
        return cls(s[0], mask)


# Turns string ipv4 into int. Expects input to have format: '255.255.255.255'
def ipv4_to_int(s: str) -> int:
    return sum([int(num) << offset for num, offset in zip(s.split('.'), range(24, -1, -8))])


# Turns int into ipv4 string. Expects input to be 0 < inp < 4 294 967 295
def int_to_ipv4(s: int) -> str:
    return '.'.join([str(s >> i & 255) for i in range(24, -1, -8)])


# Turns string ipv4 to bytes. Expects input to have format: '255.255.255.255'
def ipv4_to_bytes(s: str) -> bytes:
    return bytes([int(i) for i in s.split('.')])


# Turns bytes into ipv4 string. Expects input to be b'\x00\x00\x00\x00' < inp < b'\xff\xff\xff\xff'
def bytes_to_ipv4(s: bytes) -> str:
    return '.'.join([str(i) for i in s])


def get_bytes_to_mac(b, default=None) -> str:
    return ':'.join("%02x" % i for i in b) if isinstance(b, bytes) else default


def bytes_to_mac(b: bytes) -> str:
    return ':'.join("%02x" % i for i in b)


# Turns int into mac. Expects input to be 0 < inp < 281 474 976 710 655
# TODO: make more optimal
def int_to_mac(s: int) -> str:
    return ':'.join(['0'*(2-len(a := hex(i)[2:])) + a for i in s.to_bytes(6, 'big')])


# Turns string mac into int. Expects input to have format: ff:ff:ff:ff:ff:ff
# TODO: make more optimal
def mac_to_int(mac: str) -> int:
    return int('0x' + ''.join(mac.split(':')), 16)


# Turns string mac to bytes. Expects input to have format: ff:ff:ff:ff:ff:ff
def mac_to_bytes(mac: str) -> bytes:
    return binascii.unhexlify(mac.replace(':', ''))


# Checks if given string is an ipv4 address. Doesn't account for mask, i think
def is_ipv4(s: str) -> bool:
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


# Checks if given string is a mac address
def is_mac(s: str) -> bool:
    a = s.lower().split(':')
    if len(a) != 6:
        return False
    for i in a:
        for j in i:
            if j>"f" or (j<"a" and not j.isdigit()) or len(i)!=2:
                return False
    return True


# It's an int with an extra flag. Only used in rules, packets from network use simple int
class Int(int):
    not_flag = False


# It's bytes with extra flag. Only used in rules, packets from network use simple bytes
class Bytes(bytes):
    not_flag = False


# Returns True when compared to anything but None.
# I don't know what it returns when None, but it works. Can add additional return to be sure
class Any:
    not_flag = False

    def __eq__(self, other):
        if other is not None:
            return True

    def __repr__(self):
        if self.not_flag:
            return 'NONE'
        return 'ANY'


# Exception for malformed packets
class MalformedPacketException(Exception):
    name = 'MALFORMED'

    def __init__(self, desc):
        self.desc = desc

    def get_all_fields(self, all=False, repr=False):
        return {}

    def get_full_names(self):
        return {}

    def summary(self):
        return self.name
