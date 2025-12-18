#!/usr/bin/env python3
"""
Simple network scanner to find all devices on your network
"""
from scapy.all import ARP, Ether, srp
import sys

def scan_network(network_range):
    """
    Scan network and return list of devices with IP and MAC
    """
    print(f"[*] Scanning network: {network_range}")
    print("[*] This may take 30-60 seconds...\n")
    
    # Create ARP request for entire subnet
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    # Send packets and get responses
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
    
    return devices

def identify_device_type(mac):
    """
    Identify device type based on MAC address
    """
    # First 3 bytes identify manufacturer
    oui = mac.upper()[:8]
    
    # Common Apple OUIs (first 3 bytes)
    apple_ouis = [
        '00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:0D:93',
        '00:10:FA', '00:11:24', '00:13:E3', '00:14:51', '00:16:CB',
        '00:17:F2', '00:19:E3', '00:1B:63', '00:1C:B3', '00:1D:4F',
        '00:1E:52', '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9',
        '00:22:41', '00:23:12', '00:23:32', '00:23:6C', '00:23:DF',
        '00:24:36', '00:25:00', '00:25:4B', '00:25:BC', '00:26:08',
        '00:26:4A', '00:26:B0', '00:26:BB', '04:0C:CE', '04:15:52',
        '04:1E:64', '04:26:65', '04:48:9A', '04:4B:ED', '04:DB:56',
        '04:E5:36', '04:F1:3E', '04:F7:E4', '08:00:07', '08:66:98',
        '08:70:45', '08:74:02', '0C:3E:9F', '0C:4D:E9', '0C:77:1A',
        '10:93:E9', '10:DD:B1', '14:10:9F', '14:5A:05', '14:8F:C6',
        '18:34:51', '18:65:90', '18:AF:61', '18:E7:F4', '1C:AB:A7',
        '20:3C:AE', '20:AB:37', '24:A0:74', '24:AB:81', '24:F0:94',
        '28:37:37', '28:6A:BA', '28:A0:2B', '28:E0:2C', '28:E1:4C',
        '2C:1F:23', '2C:B4:3A', '30:10:E4', '30:35:AD', '30:63:6B',
        '30:90:AB', '34:12:98', '34:15:9E', '34:36:3B', '34:A3:95',
        '34:C0:59', '38:0F:4A', '38:48:4C', '38:B5:4D', '38:C9:86',
        '3C:07:54', '3C:15:C2', '3C:2E:F9', '40:30:04', '40:33:1A',
        '40:4D:7F', '40:A6:D9', '40:B3:95', '44:2A:60', '44:4C:0C',
        '44:D8:84', '48:43:7C', '48:60:BC', '48:74:6E', '48:A1:95',
        '48:D7:05', '4C:7C:5F', '4C:8D:79', '50:EA:D6', '54:26:96',
        '54:72:4F', '54:AE:27', '58:40:4E', '58:55:CA', '5C:95:AE',
        '5C:F9:38', '60:03:08', '60:33:4B', '60:69:44', '60:C5:47',
        '60:F8:1D', '64:20:0C', '64:76:BA', '64:A3:CB', '64:E6:82',
        '68:96:7B', '68:A8:6D', '68:D9:3C', '68:FE:F7', '6C:40:08',
        '6C:70:9F', '6C:96:CF', '6C:AB:05', '70:11:24', '70:3E:AC',
        '70:56:81', '70:73:CB', '70:DE:E2', '74:E1:B6', '74:E2:F5',
        '78:31:C1', '78:67:D7', '78:7B:8A', '78:A3:E4', '78:CA:39',
        '78:FD:94', '7C:01:91', '7C:6D:F8', '7C:C3:A1', '7C:D1:C3',
        '80:00:6E', '80:49:71', '80:92:9F', '80:E6:50', '84:38:35',
        '84:78:8B', '84:85:06', '84:89:AD', '84:FC:FE', '88:1F:A1',
        '88:53:95', '88:63:DF', '88:66:5A', '88:E8:7F', '8C:00:6D',
        '8C:2D:AA', '8C:58:77', '8C:7C:92', '8C:85:90', '8C:FA:BA',
        '90:27:E4', '90:72:40', '90:84:0D', '90:B0:ED', '90:B9:31',
        '94:E9:6A', '94:F6:A3', '98:03:D8', '98:D6:BB', '98:E0:D9',
        '98:FE:94', '9C:04:EB', '9C:20:7B', '9C:35:5B', '9C:84:BF',
        '9C:F4:8E', 'A0:18:28', 'A0:99:9B', 'A4:31:35', 'A4:5E:60',
        'A4:B1:97', 'A4:D1:8C', 'A8:20:66', 'A8:66:7F', 'A8:88:08',
        'A8:96:8A', 'A8:FA:D8', 'AC:1F:74', 'AC:29:3A', 'AC:3C:0B',
        'AC:61:EA', 'AC:87:A3', 'AC:BC:32', 'AC:CF:5C', 'B0:34:95',
        'B0:65:BD', 'B4:18:D1', 'B4:8B:19', 'B4:F0:AB', 'B4:F6:1C',
        'B8:09:8A', 'B8:17:C2', 'B8:41:A4', 'B8:53:AC', 'B8:78:2E',
        'B8:C7:5D', 'B8:E8:56', 'B8:FF:61', 'BC:3B:AF', 'BC:52:B7',
        'BC:67:1C', 'BC:6C:21', 'BC:9F:EF', 'C0:63:94', 'C0:84:7D',
        'C0:9F:42', 'C0:B6:58', 'C0:CC:F8', 'C0:CE:CD', 'C4:2C:03',
        'C8:1E:E7', 'C8:33:4B', 'C8:69:CD', 'C8:85:50', 'C8:B5:B7',
        'C8:BC:C8', 'C8:D0:83', 'CC:08:8D', 'CC:20:E8', 'CC:25:EF',
        'CC:29:F5', 'CC:2D:B7', 'CC:78:5F', 'D0:03:4B', 'D0:23:DB',
        'D0:25:98', 'D0:33:11', 'D0:4F:7E', 'D0:A6:37', 'D0:C5:F3',
        'D0:E1:40', 'D4:61:9D', 'D4:90:9C', 'D4:A3:3D', 'D4:DC:CD',
        'D4:F4:6F', 'D8:00:4D', 'D8:30:62', 'D8:9E:3F', 'D8:A2:5E',
        'D8:BB:2C', 'D8:CF:9C', 'DC:2B:2A', 'DC:2B:61', 'DC:37:42',
        'DC:3C:84', 'DC:56:E7', 'DC:86:D8', 'DC:9B:9C', 'E0:5F:45',
        'E0:66:78', 'E0:89:9D', 'E0:AC:CB', 'E0:B5:2D', 'E0:B9:BA',
        'E0:C7:67', 'E0:F5:C6', 'E0:F8:47', 'E4:25:E7', 'E4:8B:7F',
        'E4:9A:79', 'E4:CE:8F', 'E4:E4:AB', 'E8:04:0B', 'E8:80:2E',
        'E8:B2:AC', 'EC:35:86', 'EC:85:2F', 'F0:18:98', 'F0:24:75',
        'F0:98:9D', 'F0:B4:79', 'F0:CB:A1', 'F0:D1:A9', 'F0:DB:E2',
        'F0:DC:E2', 'F0:F6:1C', 'F4:0F:24', 'F4:37:B7', 'F4:5C:89',
        'F4:F1:5A', 'F4:F9:51', 'F8:1E:DF', 'F8:27:93', 'F8:2D:7C',
        'FC:25:3F', 'FC:E9:98', 'FC:FC:48',
    ]
    
    for oui in apple_ouis:
        if mac.upper().startswith(oui):
            return "Apple Device (iPhone/iPad/Mac)"
    
    return "Unknown"

if __name__ == "__main__":
    # Your network range - change this if different
    network = "10.0.0.0/24"
    
    print("=" * 60)
    print("Network Device Scanner")
    print("=" * 60)
    print()
    
    devices = scan_network(network)
    
    if not devices:
        print("[-] No devices found!")
        sys.exit(1)
    
    print(f"\n[+] Found {len(devices)} device(s):\n")
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Device Type'}")
    print("-" * 70)
    
    for device in devices:
        device_type = identify_device_type(device['mac'])
        print(f"{device['ip']:<15} {device['mac']:<20} {device_type}")
    
    print()
    print("[*] Look for 'Apple Device' to find your iPhone")
