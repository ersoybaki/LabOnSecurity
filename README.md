# 2IC80 Lab on Security - Group 31

## Man-in-the-Middle (MITM) Attack Tool

This tool implements a suite of MITM attacks including ARP Cache Poisoning, DNS Spoofing, and SSL Stripping. It allows an attacker to intercept, redirect, and modify traffic between a victim and the gateway in a virtualized network environment.

### Disclamer

**For educational purposes only.** This tool is developed for the 2IC80 Lab on Security. Do not use this against any network or device you do not own or have explicit permission to test.

### Requirements

- VMwware Workstation Pro
- Two Ubuntu Virtual Machines
  - Attacker VM
  - Victim VM
- Both VMs must be on the same virtual network (NAT or Host-only)
- On Attacker VM:
  - Python 3
  - Python3-scapy
  - Wireshark

## Common Setup

### Step 1 - Network Setup

1. Power off both virtual machines.
2. Open VM settings for both VMs.
3. Go to Network Adapter.
4. Select NAT or Host-only.
5. Ensure both VMs use the same network mode and started on the same device.
6. Start both VMs.

Note: If you want to run 2 VMs on 2 seperate devices, NAT or Host-only adapter modes will not work.

### Step 2 - Verify connectivity

- On both VMs:
  - Run: `ip a`
  - Note down the IP addresses of VMs
- Test connectivity
  - From Attacker VM: ping <Victim_IP>
  - From Victim VM: ping <Attacker_IP>
- Both must succeed.

### Step 3 - Install required tools (Attacker VM)

- `sudo apt update`
- `sudo apt install python3-scapy`
- `sudo apt install wireshark`

### Step 4 - Enable IP fowarding (Attacker VM)

- `sudo sysctl -w net.ipv4.ip_forward=1`
- Verify: `cat /proc/sys/net/ipv4/ip_forward`
- Output must be: 1

### Step 5: Find gateway IP

- On Attacker VM: `ip route`
- Look for the default gateway line and note the **Gateway IP**

### Step 6: Start Wireshark

1. Open Wireshark
2. Select interface ens33
3. Select capture
4. Apply filter: _arp_

# Attack Modes

The tool works in three modes. All commands must be run with `sudo` permissons.

## Mode A: ARP Spoofing Attack

### Step 1: Running the attack

1. Open a new terminal
2. Navigate to the folder containing the scripts
3. Run the command `sudo python3 main.py --mode arp --victim <VICTIM_IP> --gateway <GATEWAY_IP> --op-mode <silent|allout|default>`
4. Verify the output "[+] Starting ARP Spoofing..."

### Step 2: Verify the attack

- On Victim VM: `arp -a`
- The gateway IP should now resolve the attacker's MAC address

- In Wireshark: Observe repeated ARP reply packets **(opcode 2)**.

### Step 3: Reset and test again

- On Victim VM: `sudo ip neigh flush all`
- Optional: `sudo systemctl restart NetworkManager`

## Mode B: DNS Spoofing

Redirects the victim to a fake website whjen they try to visit a specific domain.

### Step 1: Trap Preparation

On Attacker VM:

- `echo "<h1>YOU HAVE BEEN HACKED</h1>" > index.html` to create the fake webpage.
- `sudo python3 -m http.server 80` start the server on port 80.
  Keep the terminal open at Attacker VM. When it show log entries "GET / HTTP/1.1" 200, it means the victim is connected.

### Step 2: Run the DNS poisoning attack

On Attacker VM:

1. Open a new terminal.
2. Navigate to the folder containing the scripts.
3. `sudo python3 main.py --mode dns --victim <VICTIM_IP> --gateway <GATEWAY_IP> --attacker <ATTACKER_IP> --target-domain <www.example.com> --op-mode <silent|allout|default>` to run the tool.
4. Verify the output:

- "[+] Arp Spoofing started..." and
- "[+] DNS Sniffer started..."

### Step 3: Testing the attack

On Victim VM:

1. `sudo resolvectl flush-caches` to clear the DNS cahce before testing.(Must clear it befor testing)
2. Test:

- OPTION A
  - `ping <TARGET_DOMAIN>`
    After pingin the taget domain from Victim VM, if the response is coming from <ATTACKER_IP>, it means attack succeeded.
- OPTION B
  - Open Firefox and visit http://<TARGET_DOMAIN>
  - You should see the "YOU HAVE BEEN HACKED" page.
    Note: Use HTTP not HTTPS because at this point of our attack we have not set up SSL Stripping yet.

## Mode C: SSL Stripping

Downgrades HTTPS connections to HTTP to steal credientials

### Step 1: Run the SSL stripping attack

1. Open a new terminal.
2. Navigate to the folder containing the scripts.
3. `sudo python3 main.py --mode ssl --victim <VICTIM_IP> --gateway <GATEWAY_IP> --interface <INTERFACE_NAME> --op-mode <silent|allout|default>` to run the tool.
4. Verify the output: "[+] Starting SSL Stripping on <INTERFACE_NAME>"

### Step 2: Test the Attack ():

On Victim VM:

- OPTION A
  - `curl -I -L http://testphp.vulnweb.com/login.php`
  - Success: Output shows `HTTP/1.1 200 OK` and No `Strict-Transport-Secuirty` header present.
- OPTION B
  - Open browser on Victim VM
  - Go to `http://testphp.vulnweb.com/login.php` (or any non-HSTS website)
  - Enter a username and password
  - Success: Check the attacker terminal. You will see the raw username and password you entered

## Operational Modes

The tool supports different operational modes to simulate different attacker behaviors, ranging from stealthy monitoring to aggressive disruption. Use the `--op-mode` flag to select a mode.

### 1. Silent Mode

Designed to remain undetected by Intrusion Detection Systems (IDS) and users.

- **Command:** `--op-mode silent`
- **ARP:** Low frequency packets (every 5 seconds) to minimize network noise.
- **DNS:** Only spoofs the specific target domain provided.
- **SSL:** Passive monitoring only. It listens for unencrypted traffic but does **not** actively strip HTTPS or modify packets to avoid triggering browser warnings.
- **Output:** Suppresses console output to keep the terminal clean. Logs sensitive data/credentials to `sslstrip.log`.

### 2. All-Out Mode

Designed for maximum impact and ensuring interception even on busy networks.

- **Command:** `--op-mode all-out`
- **ARP:** High frequency flooding (every 1 seconds) to aggressively poison the cache and fight against router corrections.
- **DNS:** Wildcard spoofing. Redirects **ALL** DNS queries from the victim to the attacker, regardless of the domain requested.
- **SSL:** Active SSL Stripping. Forces HTTPS connections down to HTTP using `NFQUEUE` and attempts to bypass HSTS headers.
- **Output:** Verbose console output showing all intercepted headers, modifications, and traffic details.

### Notes:

- **NAT and Host-only modes are safe.**
- **Do not use Bridged mode.**
- **Always run these attack only in controlled lab environments.**
