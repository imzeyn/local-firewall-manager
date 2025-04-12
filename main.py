import subprocess
import socket
import time
import os
import mysql.connector
from datetime import datetime

# MySQL connection settings
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "password",  # Replace with your MySQL password
    "database": "firewall_logs"
}

# Interval to check the whitelist (in seconds)
CHECK_INTERVAL = 300

class Logger:
    def __init__(self, log_file="firewall_blocked.log"):
        self.log_file = log_file

    # Write log to file and MySQL
    def write_log(self, ip, port, protocol, reason):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Write log to file
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] BLOCKED {ip}:{port} ({protocol}) - {reason}\n")

        # Write log to MySQL database
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            query = "INSERT INTO logs (timestamp, ip, port, protocol, reason) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (timestamp, ip, port, protocol, reason))
            conn.commit()
            cursor.close()
            conn.close()
        except mysql.connector.Error as err:
            print(f"[!] MySQL error: {err}")

class DNSResolver:
    @staticmethod
    def resolve_domain_to_ips(domain):
        try:
            # Resolve the domain to IPs (A records)
            return socket.gethostbyname_ex(domain)[2]
        except Exception as e:
            print(f"[!] DNS resolution failed: {domain} ({e})")
            return []

class FirewallManager:
    def __init__(self, trusted_dns_file="trusted_dns_list.txt"):
        # Read trusted DNS from the file
        self.trusted_dns = self.read_list(trusted_dns_file)
        self.current_ips = set()  # To track allowed IPs
        self.domain_ip_map = {}  # To map domains to resolved IPs

    def read_list(self, file_path):
        # Read a list from a file and remove empty lines and comments
        if not os.path.exists(file_path):
            return []
        with open(file_path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def run_command(self, cmd):
        # Run a shell command
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass  # Ignore errors if the rule already exists

    def iptables_reset(self):
        # Reset iptables, drop all outgoing connections, and allow loopback
        self.run_command(["sudo", "iptables", "-F"])
        self.run_command(["sudo", "iptables", "-P", "OUTPUT", "DROP"])
        self.run_command(["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    def allow_dns_servers(self):
        # Allow outgoing DNS queries to trusted DNS servers
        for dns in self.trusted_dns:
            self.run_command(["sudo", "iptables", "-A", "OUTPUT", "-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT"])
            self.run_command(["sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT"])

    def allow_ip(self, ip):
        # Allow outgoing traffic to the given IP
        self.run_command(["sudo", "iptables", "-C", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
        self.run_command(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])

    def remove_ip(self, ip):
        # Remove the rule that allows traffic to the given IP
        self.run_command(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "ACCEPT"])

    def is_ip(self, text):
        # Check if the given text is a valid IP address
        return all(c.isdigit() or c == "." for c in text)

    def process_whitelist(self, whitelist, logger):
        # Process the whitelist and update iptables
        for item in whitelist:
            if self.is_ip(item):  # If it's an IP address
                if item not in self.current_ips:
                    self.allow_ip(item)
                    self.current_ips.add(item)
            else:  # If it's a domain
                # Resolve domain to IP addresses
                new_ips = set(DNSResolver.resolve_domain_to_ips(item))
                old_ips = self.domain_ip_map.get(item, set())

                if new_ips != old_ips:
                    to_remove = old_ips - new_ips
                    to_add = new_ips - old_ips

                    # Remove old IPs and add new IPs
                    for ip in to_remove:
                        self.remove_ip(ip)
                        self.current_ips.discard(ip)

                    for ip in to_add:
                        self.allow_ip(ip)
                        self.current_ips.add(ip)

                    self.domain_ip_map[item] = new_ips
                    # Log the IP change
                    for ip in to_add:
                        logger.write_log(ip, None, "TCP/UDP", "Domain IP changed")

class FirewallDaemon:
    def __init__(self, whitelist_file="whitelist.txt"):
        # Initialize the daemon with the whitelist file
        self.whitelist_file = whitelist_file
        self.logger = Logger()
        self.firewall_manager = FirewallManager()

    def start(self):
        # Start the firewall service
        print("[*] Initializing settings...")
        self.firewall_manager.iptables_reset()
        self.firewall_manager.allow_dns_servers()

        print("[*] Firewall service started. Whitelist will be checked every 5 minutes.")
        
        while True:
            # Read the whitelist and process it
            whitelist = self.firewall_manager.read_list(self.whitelist_file)
            self.firewall_manager.process_whitelist(whitelist, self.logger)
            print(f"[✓] Whitelist updated.")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    # Start the firewall daemon
    daemon = FirewallDaemon()
    daemon.start()
