from .__constants import LL_TYPES

from . import arp
from . import dhcp
from . import dot1x_authentication
from . import dot11_header
from . import dot11_management
from . import eap
from . import ethernet
from . import ipv4
from . import llc
from . import radiotap
from . import udp


PROTOS_CONSTRUCTOR = {'arp': arp.arp,
                      'dhcp': dhcp.dhcp,
                      'dot1x_authentication': dot1x_authentication.dot1x_authentication,
                      'dot11_header': dot11_header.dot11_header,
                      'dot11_management': dot11_management.dot11_management,
                      'eap': eap.eap,
                      'ethernet': ethernet.ethernet,
                      'ipv4': ipv4.ipv4,
                      'llc': llc.llc,
                      'radiotap': radiotap.radiotap,
                      'udp': udp.udp}

PROTOS_SUMMARY = {'arp': arp.summary,
                  'dhcp': dhcp.summary,
                  'dot1x_authentication': dot1x_authentication.summary,
                  'dot11_header': dot11_header.summary,
                  'dot11_management': dot11_management.summary,
                  'eap': eap.summary,
                  'ethernet': ethernet.summary,
                  'ipv4': ipv4.summary,
                  'llc': llc.summary,
                  'radiotap': radiotap.summary,
                  'udp': udp.summary}

__all__ = ['PROTOS_CONSTRUCTOR', 'PROTOS_SUMMARY', 'LL_TYPES']
