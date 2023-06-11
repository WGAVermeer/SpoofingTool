from typing import Any
import os
import ArpPoison
import threading
from scapy.all import *
from scapy.layers.http import *


def sendPacketTest():
    httpPacket = IP(dst = '8.8.8.8') / TCP(dport=80) / HTTP() / HTTPRequest(Upgrade_Insecure_Requests = 1)
    httpPacket.show()
    send(httpPacket)
    
sendPacketTest()