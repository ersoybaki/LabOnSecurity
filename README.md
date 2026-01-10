# 2IC80 Lab on Security - Group 31

## ARP Spoofing Test Guide (VMware + Ubuntu + Wireshark)
Step by step on how to reproduce the ARP spoofing attack using the provided *arp.py* script in a safe virtualized environment.

### Requirements
- VMwware Workstation Pro
- Two Ubuntu Virtual Machine
	- Attacker VM
	- Victim VM
- Both VMs must be on the same virtual network (NAT or Host-only)
- On Attacker VM:
	- Python 3
	- Python3-scapy
	- Wireshark

### Step 1 - Network Setup
1. Power off both virtual machines.
2. Open VM settings for both VMs.
3. Go to Network Adapter.
4. Select NAT or Host-only.
5. Ensure both VMs use the same network mode.
6. Start both VMs.

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
4. Apply filter: *arp*

### Step 7: Run the ARP spoofing attack
1. Navigate to the directory containing *arp.py*.
2. Modify the `__main__` section at the end of the arp.py script with the actual IP addresses
3. Run the attack script with `python3 arp.py`
4. To stop the attack, press *CTRL + C*

### Step 8: Verify the attack
- On Victim VM: `arp -a`
- The gateway IP should now resolve the attacker's MAC address

- In Wireshark: Observe repeated ARP reply packets **(opcode 2)**.

### Step 9: Reset and test again
- On Victim VM: `sudo ip neigh flush all`
- Optional: `sudo systemctl restart NetworkManager`

### Continuation of ARP spoofing, DNS poisoning Test Guide
Step by step on how to reproduce the DNS Poisoning attack with the ARP spoofing attack using the provided *arp.py*, *dns.py* and *main.py* script in a safe virtualized environment.

### Step 10: Trap Preparation
On Attacker VM: 
- `echo "<h1>YOU HAVE BEEN HACKED</h1>" > index.html` to create the fake webpage.
- `sudo python3 -m http.server 80` start the server on port 80.
Keep the terminal open at Attacker VM. When it show log entries "GET / HTTP/1.1" 200, it means the victim is connected.

### Step 11: Run the DNS poisoning attack
On Attacker VM:
1. Open a new terminal.
2. Navigate to the folder containing the scripts.
3. `sudo python3 main.py --victim <VICTIM_IP> --gateway <GATEWAY_IP> --attacker <ATTACKER_IP> --target-domain www.example.com` to run the tool.
4. Verify the output:
- "[+] Arp Spoofing started..." and 
- "[+] DNS Sniffer started..."

### Step 12: Testing the attack
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




### Notes:
- **NAT and Host-only modes are safe.**
- **Do not use Bridged mode.**
- **Always run these attack only in controlled lab environments.**


