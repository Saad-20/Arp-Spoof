#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # converting packet to scapy packet i.e. IP layer
    if scapy_packet.haslayer(scapy.DNSRR):
        print(scapy_packet.show())  # print details of the scapy_packet
    packet.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0,process_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function
