#!/usr/bin/env python3
import subprocess
import json
import time
from datetime import datetime
import threading
from collections import defaultdict

class TrafficMonitor:
    def __init__(self):
        self.packet_stats = defaultdict(int)
        self.connection_stats = defaultdict(int)
        self.suspicious_ips = set()
        self.alert_threshold = 100  # Number of packets per second to trigger alert
        
    def start_capture(self, interface="any"):
        """Start capturing packets using tshark"""
        # tshark command with JSON output format
        cmd = [
            "tshark",
            "-i", interface,
            "-T", "json",
            "-l",  # Line buffered output
            "-f", "ip",  # Capture only IP packets
            "-n"  # No name resolution
        ]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            print(f"Started capturing traffic on interface {interface}")
            return process
        except Exception as e:
            print(f"Error starting tshark: {e}")
            return None

    def analyze_packet(self, packet_data):
        """Analyze a single packet for suspicious patterns"""
        try:
            # Extract basic packet information
            source_ip = packet_data.get('_source', {}).get('layers', {}).get('ip', {}).get('ip.src', '')
            dest_ip = packet_data.get('_source', {}).get('layers', {}).get('ip', {}).get('ip.dst', '')
            protocol = packet_data.get('_source', {}).get('layers', {}).get('ip', {}).get('ip.proto', '')
            
            if not source_ip or not dest_ip:
                return
            
            # Update packet statistics
            self.packet_stats[source_ip] += 1
            connection_key = f"{source_ip}->{dest_ip}"
            self.connection_stats[connection_key] += 1
            
            # Check for potential suspicious activity
            if self.packet_stats[source_ip] > self.alert_threshold:
                if source_ip not in self.suspicious_ips:
                    self.suspicious_ips.add(source_ip)
                    self.alert_suspicious_activity(source_ip)
            
        except Exception as e:
            print(f"Error analyzing packet: {e}")

    def alert_suspicious_activity(self, ip):
        """Generate an alert for suspicious activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[ALERT] {timestamp}")
        print(f"Suspicious activity detected from IP: {ip}")
        print(f"Packet count: {self.packet_stats[ip]}")
        print("Recent connections:")
        for conn, count in self.connection_stats.items():
            if ip in conn:
                print(f"  {conn}: {count} packets")

    def monitor_traffic(self):
        """Main monitoring loop"""
        process = self.start_capture()
        if not process:
            return
        
        try:
            while True:
                # Read a line from tshark output
                line = process.stdout.readline()
                if not line:
                    break
                try:
                    packet_data = json.loads(line)
                    # If packet_data is a list, process each item
                    if isinstance(packet_data, list):
                        for pkt in packet_data:
                            self.analyze_packet(pkt)
                    else:
                        self.analyze_packet(packet_data)
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing packet: {e}")
        except KeyboardInterrupt:
            print("\nStopping traffic monitoring...")
        finally:
            process.terminate()
            process.wait()

    def print_stats(self):
        """Print current statistics periodically"""
        while True:
            time.sleep(10)  # Print stats every 10 seconds
            print("\n=== Traffic Statistics ===")
            print(f"Total unique IPs: {len(self.packet_stats)}")
            print(f"Suspicious IPs: {len(self.suspicious_ips)}")
            print("\nTop 5 source IPs by packet count:")
            for ip, count in sorted(self.packet_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ip}: {count} packets")
            print("========================\n")

def main():
    monitor = TrafficMonitor()
    
    # Start statistics printing in a separate thread
    stats_thread = threading.Thread(target=monitor.print_stats, daemon=True)
    stats_thread.start()
    
    # Start the main monitoring loop
    monitor.monitor_traffic()

if __name__ == "__main__":
    main() 