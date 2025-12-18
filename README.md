# Lab on Security — MITM Attack Tool

A Python-based Man-in-the-Middle (MITM) attack tool demonstrating ARP spoofing, DNS spoofing, and SSL stripping techniques.

### Implemented Features

#### ARP Spoofing
- **MAC Address Discovery**: Automatically discover devices on the local network using ARP requests
- **Bidirectional ARP Cache Poisoning**: Poison both victim and gateway ARP caches to position attacker as MITM
- **Proper Packet Crafting**: Uses both Ethernet and ARP layers for reliable spoofing
- **Safe Cleanup**: Automatically restores original ARP tables when attack is stopped

**How it works:**
1. Sends ARP replies to victim claiming to be the gateway
2. Sends ARP replies to gateway claiming to be the victim
3. All traffic flows through attacker's machine
4. Enables traffic interception and analysis

## Installation

### Prerequisites
- Python 3.7+
- Administrator/root privileges (required for raw packet manipulation)
- Windows, Linux, or macOS

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ersoybaki/LabOnSecurity.git
   cd LabOnSecurity
   ```

2. **Create virtual environment (recommended):**
   ```bash
   python -m venv .venv
   ```

3. **Activate virtual environment:**
   ```powershell
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   
   # Linux/Mac
   source .venv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Network Scanner

First, identify devices on your network:

```bash
python scan_network.py
```

This will display all devices with their IP addresses, MAC addresses, and device types (identifies Apple devices).

### ARP Spoofing Test

⚠️ **IMPORTANT:** Only run this in a controlled test environment with devices you own!

#### Step 1: Enable IP Forwarding

**Windows (PowerShell as Administrator):**
```powershell
Set-NetIPInterface -Forwarding Enabled
```

**Linux:**
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

**macOS:**
```bash
sudo sysctl -w net.inet.ip.forwarding=1
```

#### Step 2: Configure Target

Edit `test_arp.py` and set your network configuration:
```python
target_ip = "10.0.0.XXX"    # Victim device IP
gateway_ip = "10.0.0.1"     # Router/Gateway IP
```

#### Step 3: Run Test

**Option 1: MAC Address Discovery (Safe - No Admin Required)**
```bash
python test_arp.py
# Choose option 1
```

**Option 2: Full ARP Spoofing Attack (Requires Admin/Root)**
```bash
# Windows: Run PowerShell as Administrator
# Linux/Mac: Use sudo
python test_arp.py
# Choose option 2
```

#### Step 4: Monitor Traffic (Optional)

While the attack is running, use Wireshark to capture traffic:

1. Open Wireshark on your WiFi interface
2. Apply filter: `ip.addr == [VICTIM_IP]`
3. Observe all victim traffic flowing through your machine

**Useful Wireshark filters:**
```
# All traffic from victim
ip.addr == 10.0.0.XXX

# DNS queries
dns and ip.src == 10.0.0.XXX

# HTTP traffic (unencrypted)
http.request and ip.src == 10.0.0.XXX

# Search for keywords
frame contains "keyword"

# HTTPS domains visited
tls.handshake.extensions_server_name
```

#### Step 5: Stop Attack

Press **Ctrl+C** - the script will automatically restore original ARP tables.

### What to Observe

**On Victim Device:**
- Internet continues working normally (if IP forwarding is enabled)
- No visible indication of attack
- ARP cache shows attacker's MAC for gateway IP (check with `arp -a`)

**On Attacker Machine:**
- Packet counter increases every 2 seconds
- All victim traffic visible in Wireshark
- Can see: DNS queries, HTTP content, HTTPS domains, all network activity

**Expected Output:**
```
[*] ARP Spoofing Test
[*] Target IP: 10.0.0.XXX
[*] Gateway IP: 10.0.0.1

[*] Step 1: Discovering MAC addresses...
[+] Target MAC: xx:xx:xx:xx:xx:xx
[+] Gateway MAC: xx:xx:xx:xx:xx:xx

[*] Step 2: Reminder - Enable IP forwarding!
...

[*] Step 3: Starting ARP spoofing attack...
[*] Press Ctrl+C to stop

[+] Packets sent: 2
[+] Packets sent: 4
[+] Packets sent: 6
...

^C
[*] Stopping ARP spoofing...
[*] Restoring ARP tables...
[+] ARP tables restored
[+] Attack stopped safely
```

## Testing Scenarios

### Test 1: Basic Connectivity Test
1. Run ARP spoofing attack
2. Browse websites on victim device
3. Verify internet still works (IP forwarding enabled)
4. Observe traffic in Wireshark

### Test 2: HTTP Traffic Interception
1. Run ARP spoofing attack
2. On victim device, visit `http://neverssl.com`
3. In Wireshark: Right-click packet → Follow → HTTP Stream
4. See entire HTTP conversation in plaintext

### Test 3: HTTPS Metadata Collection
1. Run ARP spoofing attack
2. On victim device, search for something on Google
3. In Wireshark, filter: `dns` or `tls.handshake.extensions_server_name`
4. See domain names visited (even though content is encrypted)

## Technical Details

### ARP Spoofing Implementation

**File:** `mitmtool/arp.py`

**Key Functions:**
- `get_mac(ip)`: Send ARP request and retrieve MAC address
- `spoof(target_ip, spoof_ip, target_mac)`: Send poisoned ARP reply

**Packet Structure:**
```python
Ethernet Layer: dst=target_mac
ARP Layer:      op=2 (is-at reply)
                pdst=target_ip
                hwdst=target_mac
                psrc=spoof_ip (impersonated address)
```

**Attack Flow:**
```
Every 2 seconds:
  1. Tell Victim: "Gateway IP is at Attacker MAC"
  2. Tell Gateway: "Victim IP is at Attacker MAC"
  
Result: All traffic flows Victim ↔ Attacker ↔ Gateway
```

## Security Implications

This tool demonstrates why the following security measures are important:

### Vulnerabilities Exploited
- **ARP has no authentication**: Any device can claim to be any IP
- **Stateless protocol**: Unsolicited ARP replies are accepted
- **Cache poisoning**: ARP tables updated without verification

### Defenses Demonstrated
- **HTTPS/TLS**: Content remains encrypted even during MITM
- **HSTS**: Prevents SSL stripping on supporting sites
- **Certificate Pinning**: Apps can detect MITM attempts
- **Static ARP entries**: Prevent ARP cache poisoning
- **ARP spoofing detection tools**: Monitor for duplicate MACs

## Troubleshooting

**Attack not working:**
- Ensure running as Administrator/root
- Verify IP addresses are correct
- Check that devices are on same network
- Confirm target device is online (`ping` first)

**Victim loses internet connection:**
- IP forwarding not enabled
- Run: `Set-NetIPInterface -Forwarding Enabled` (Windows Admin PowerShell)

**No traffic in Wireshark:**
- Check you're capturing on correct interface (WiFi)
- Verify filter syntax: `ip.addr == X.X.X.X`
- Ensure ARP poisoning is active (check packet counter)

**Scapy warnings:**
- Update to latest version: `pip install --upgrade scapy`
- Ensure WinPcap/Npcap installed (Windows)

## Roadmap

- [x] ARP spoofing with MAC discovery
- [x] Network device scanner
- [x] Test suite for ARP attacks
- [ ] DNS spoofing implementation
- [ ] SSL stripping implementation
- [ ] Main CLI interface with mode selection
- [ ] Configuration file support
- [ ] Traffic logging to PCAP
- [ ] Web dashboard for statistics
- [ ] Automatic target discovery
