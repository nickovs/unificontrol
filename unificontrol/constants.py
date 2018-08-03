from enum import Enum

class RadiusTunnelType(Enum):
    """Values for the tunnel type in RADIUS profiles"""
    PPTP      =  1 #: Point-to-Point Tunneling Protocol
    L2F       =  2 #:  Layer Two Forwarding
    L2TP      =  3 #:  Layer Two Tunneling Protocol
    ATMP      =  4 #:  Ascend Tunnel Management Protocol
    VTP       =  5 #:  Virtual Tunneling Protocol
    AH        =  6 #:  IP Authentication Header in the Tunnel-mode
    IP_IP     =  7 #:  IP-in-IP Encapsulation
    MIN_IP_IP =  8 #:  Minimal IP-in-IP Encapsulation
    ESP       =  9 #:  IP Encapsulating Security Payload in the Tunnel-mode
    GRE       = 10 #:  Generic Route Encapsulation
    DVS       = 11 #:  Bay Dial Virtual Services
    IP_IP_TUN = 12 #: IP-in-IP Tunneling
    VLAN      = 13 #: Virtual LANs

class RadiusTunnelMediumType(Enum):
    """Values for the tunnel medium type in RADIUS profiles"""
    IPv4       = 1  #: IP version 4
    IPv6       = 2  #: IP version 6
    NSAP       = 3  #: NSAP
    HDLC       = 4  #: 8-bit multidrop
    BBN        = 5  #: 1822
    IEEE_802   = 6  #: includes all 802 media plus Ethernet "canonical format"
    E_163      = 7  #: E.163 (POTS)
    E_164      = 8  #: E.164 (SMDS, Frame Relay, ATM)
    F_69       = 9  #: F.69 (Telex)
    X_121      = 10 #: X.121 (X.25, Frame Relay)
    IPX        = 11 #: IPX
    APPLETALK  = 12 #:Appletalk
    DECNET     = 13 #: Decnet IV
    BANYAN     = 14 #: Banyan Vines
    E_164_NSAP = 15 #: E.164 with NSAP format subaddress
