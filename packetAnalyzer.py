from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import ICMP


def getMacAddr(mac_bytes):
    if isinstance(mac_bytes, bytes):
        return ":".join("{:02x}".format(b) for b in mac_bytes)
    elif isinstance(mac_bytes, str):
        return mac_bytes
    else:
        raise TypeError(f"Expected bytes, got {type(mac_bytes)}")


def packet_handler(packet):
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print("-" * 50)
        print(f"Destination MAC : {getMacAddr(eth.dst)} Source MAC : {getMacAddr(eth.src)} Protocol : {eth.type}")

        if eth.type == 0x0800:  # IP protocol
            ip = packet[IP]
            print(
                f"Version : {ip.version} IP Header Length : {ip.ihl} TTL : {ip.ttl} Protocol : {ip.proto} Source IP : {ip.src} Destination IP : {ip.dst}")

            if ip.proto == 6:  # TCP protocol
                tcp = packet[TCP]
                print(
                    f"Source Port : {tcp.sport} Destination Port : {tcp.dport} Sequence Number : {tcp.seq} Acknowledgement Number : {tcp.ack} Header Length : {tcp.dataofs}")
                # Print out the data if present
                if len(tcp.payload):
                    print(f"Data : {bytes(tcp.payload)}")

            elif ip.proto == 17:  # UDP protocol
                udp = packet[UDP]
                print(f"Source Port : {udp.sport} Destination Port : {udp.dport} Length : {udp.len}")
                # Print out the data if present
                if len(udp.payload):
                    print(f"Data : {bytes(udp.payload)}")

            elif ip.proto == 1:  # ICMP protocol
                icmp = packet[ICMP]
                print(f"Type : {icmp.type} Code : {icmp.code} ID : {icmp.id} Sequence : {icmp.seq}")
                # Print out the data if present
                if len(icmp.payload):
                    print(f"Data : {bytes(icmp.payload)}")

            else:
                print("Other IP protocol")

        elif eth.type == 0x0806:  # ARP protocol
            arp = packet[ARP]
            print(
                f"ARP Operation : {arp.op} Source MAC : {getMacAddr(arp.hwsrc)} Source IP : {arp.psrc} Target MAC : {getMacAddr(arp.hwdst)} Target IP : {arp.pdst}")

        else:
            print("Non-IP or unknown protocol")


if __name__ == "__main__":
    try:
        sniff(prn=packet_handler, store=0)  # Capture packets and process with packet_handler function
    except Exception as e:
        print(f"An error occurred: {e}")
