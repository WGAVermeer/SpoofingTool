import typer

import ArpPoison;

from DNS_Spoofer import DnsSnoof

app = typer.Typer()

@app.command()
def main(name: str, hasallcaps: bool = False):
    if hasallcaps:
        print(f"HELLO {name.upper()}")
    else:
        print(f"Hello {name}")

def Arp_Spoof(ipVictim: str, ipServer: str):
    main.mkspoofARP(ipVictim, ipServer)

def DNS_Spoof(ipVictim: str, orginalWebsite: str, evilWebsite: str):
    #DNS_SPoofer = DnsSnoof(ipVictim, orginalWebsite, evilWebsite) #TODO: Fix after DNS_Spoofer.py rewrite
    print("This is a placeholder, you shouldn't be seeing this!")

if __name__ == "__main__":
    app()