import typer

import ArpPoison;

#from DNS_Spoofer import DnsSnoof

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
def DNS_Spoof(ipVictim: str, orginalWebsite: str, evilWebsiteIP: str):
    #DNS_Spoofer = DnsSnoof(ipVictim, orginalWebsite, evilWebsiteIP) #TODO: Fix after DNS_Spoofer.py rewrite
    #DNS_Spoofer()
    print("This is a placeholder, you shouldn't be seeing this!")

if __name__ == "__main__":
    app()