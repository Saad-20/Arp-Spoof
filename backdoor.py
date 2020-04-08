#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def spoofed_packet(packets):
    scapy_packet = scapy.IP(packets.get_payload()) # converting packet to scapy packet i.e. IP layer
    if scapy_packet.haslayer(scapy.Raw):
        # Destination Port
        if scapy_packet[scapy.TCP].dport == 80:
            print("This is an HTTP Request")
            print(scapy_packet.show())
        # Source Port
        elif scapy_packet[scapy.TCP].sport == 80:
            print("This is an HTTP Response")
            print(scapy_packet.show())

    packets.accept()  # accept packets
queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, spoofed_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function