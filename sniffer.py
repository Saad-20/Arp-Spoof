#!/usr/bin/env python
# pip install scapy_http (requirements)
import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    # prn is callback function, thus this would allow to callback the function every time a packet is captured
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

def sniffed_packet(packets):
    if packets.haslayer(http.HTTPRequest):
        print(packets)

sniffer("wlan0")