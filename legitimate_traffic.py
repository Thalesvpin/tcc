#!/usr/bin/env python3
import time
import random
import requests
from scapy.all import *
import threading

def generate_http_traffic():
    """Generate legitimate HTTP traffic by making requests to common websites"""
    urls = [
        'http://www.google.com',
        'http://www.github.com',
        'http://www.python.org'
    ]
    
    while True:
        try:
            url = random.choice(urls)
            response = requests.get(url)
            print(f"HTTP Request to {url} - Status: {response.status_code}")
            time.sleep(random.uniform(2, 5))
        except Exception as e:
            print(f"Error in HTTP request: {e}")
            time.sleep(5)

def generate_icmp_traffic():
    """Generate ICMP (ping) traffic using Scapy"""
    target_ip = "8.8.8.8"  # Google's DNS server as an example
    
    while True:
        try:
            # Create and send ICMP packet
            packet = IP(dst=target_ip)/ICMP()
            reply = sr1(packet, timeout=2, verbose=0)
            
            if reply:
                print(f"ICMP Reply from {target_ip}: Type={reply[ICMP].type} Code={reply[ICMP].code}")
            else:
                print(f"No reply from {target_ip}")
            
            time.sleep(random.uniform(1, 3))
        except Exception as e:
            print(f"Error in ICMP traffic: {e}")
            time.sleep(5)

def generate_tcp_traffic():
    """Generate TCP traffic using Scapy"""
    target_ip = "8.8.8.8"
    target_port = 53  # DNS port as an example
    
    while True:
        try:
            # Create and send TCP SYN packet
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            reply = sr1(packet, timeout=2, verbose=0)
            
            if reply and reply.haslayer(TCP):
                print(f"TCP Reply from {target_ip}: Port {target_port} - Flags={reply[TCP].flags}")
            else:
                print(f"No TCP reply from {target_ip}:{target_port}")
            
            time.sleep(random.uniform(2, 4))
        except Exception as e:
            print(f"Error in TCP traffic: {e}")
            time.sleep(5)

def main():
    # Create threads for different types of traffic
    http_thread = threading.Thread(target=generate_http_traffic, daemon=True)
    icmp_thread = threading.Thread(target=generate_icmp_traffic, daemon=True)
    tcp_thread = threading.Thread(target=generate_tcp_traffic, daemon=True)
    
    # Start all threads
    http_thread.start()
    icmp_thread.start()
    tcp_thread.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping traffic generation...")
        # Threads will be terminated automatically as they are daemon threads

if __name__ == "__main__":
    main() 