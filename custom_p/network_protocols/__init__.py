# this file is fully auto-generated
# the changes you make will not be saved
from .llc import Llc
from .dot11_header import Dot11Header
from .dot11_management import Dot11Management
from .dot1x_authentication import Dot1xAuthentication
from .eap import Eap
from .arp import Arp
from .ether import Ether
from .ipv4 import Ipv4
from .radiotap import Radiotap
from .udp import Udp
from .dhcp import Dhcp

__all__ = ["Llc", "Dot11Header", "Dot11Management", "Dot1xAuthentication", "Eap", "Arp", "Ether", "Ipv4", "Radiotap", "Udp", "Dhcp", "get_all_names", "get_full_names", "get_all_full_names", "get_full_name"]

# Returns all protocol names including additional ones
def get_all_names():
    return {'dot11', 'dot1x_auth', 'llc', 'dot11_header', 'dot11_management', 'dot1x_authentication', 'eap', 'arp', 'ether', 'ipv4', 'radiotap', 'udp', 'dhcp'}


# Returns full names only, one per protocol
def get_all_full_names():
    return {'llc', 'dot11_header', 'dot11_management', 'dot1x_authentication', 'eap', 'arp', 'ether', 'ipv4', 'radiotap', 'udp', 'dhcp'}


# Takes list with names, returns list with full versions of them
def get_full_names(a: list):
    ret = []

    if 'dot11' in a:
        ret.append('dot11_header')
    if 'dot1x_auth' in a:
        ret.append('dot1x_authentication')
    
    return ret


# Takes a single name, returns full version of it
def get_full_name(a: str):
    if a == 'dot11':
        return 'dot11_header'
    if a == 'dot1x_auth':
        return 'dot1x_authentication'
    
    return a
