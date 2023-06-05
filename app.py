import typer

import main;


app = typer.Typer()

@app.command()
def main(name: str, hasallcaps: bool = False):
    if hasallcaps:
        print(f"HELLO {name.upper()}")
    else:
        print(f"Hello {name}")

def spoof(ipVictim: str, ipServer: str):
    main.mkspoofARP(ipVictim, ipServer)

if __name__ == "__main__":
    app()