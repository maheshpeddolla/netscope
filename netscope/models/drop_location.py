from enum import Enum


class DropLocation(Enum):

    UNKNOWN = "Unknown"

    NIC_DRIVER = "NIC Driver"

    SOFTNET = "Kernel Softnet"

    TCP = "TCP Stack"

    FIREWALL = "Firewall"

    XDP = "XDP"

    TC = "Traffic Control"

    BRIDGE = "Linux Bridge"

    BOND = "Bond"

    VLAN = "VLAN"

    OPENVSWITCH = "Open vSwitch"

    AZURE = "Azure Networking"

    APPLICATION = "Application"