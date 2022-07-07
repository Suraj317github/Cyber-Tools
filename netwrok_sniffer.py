import http
from sqlite3 import InterfaceError
from numpy import False_
import scapy.all as scapy

def sniffing(interfacce):
    scapy.sniff(iface=InterfaceError,store=False_,prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest].Host)

sniffing('Wi-Fi')