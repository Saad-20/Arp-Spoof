#!/usr/bin/env python
# pip install scapy_http (requirements)
import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    # prn is callback function, thus this would allow to callback the function every time a packet is captured.
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

# This function would be called in the prn of the sniffer function and filter data i.e. from http websites
def sniffed_packet(packets):
    if packets.haslayer(http.HTTPRequest): # This will check for http layer
        if packets.haslayer(scapy.Raw): # This will check for if the packet has a raw layer
            print(packets[scapy.Raw].load) # print the raw layer

# Capturing data from wlan0 interface
sniffer("wlan0")

# packets.show(). This would show all the types of packets passing through. Useful for printing any other type layer or
# specific field