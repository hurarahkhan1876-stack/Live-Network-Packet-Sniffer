import socket
import os
import struct

def start_sniffer():
    # Aapke PC ka local IP automatically detect karega
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"[*] Network Sniffer Started on IP: {local_ip}")
    print("-" * 50)

    try:
        # Create a raw socket to capture all incoming IP packets
        if os.name == 'nt': # Windows ke liye
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((local_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Promiscuous mode ON (Sab kuch capture karo)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else: # Linux/Mac ke liye
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sniffer.bind(("0.0.0.0", 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print("[*] Listening for live network traffic... (Press Ctrl+C to stop)\n")
        
        # Loop to continuously capture packets
        packet_count = 0
        while packet_count < 10: # Hum sirf pehle 10 packets capture karenge safety ke liye
            raw_data, addr = sniffer.recvfrom(65565)
            packet_count += 1
            
            # Print the sender's IP and the raw binary data
            print(f"[+] Packet #{packet_count} Captured!")
            print(f"    Source IP: {addr[0]}")
            print(f"    Raw Bytes (Header): {raw_data[:20]}") 
            print("-" * 40)
            
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
    except PermissionError:
        print("\n[!] PERMISSION DENIED: Sniffer chalane ke liye CMD ko 'Run as Administrator' karna zaroori hai.")
    finally:
        # Promiscuous mode OFF
        if os.name == 'nt' and 'sniffer' in locals():
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    print("-" * 50)
    print("Z1 CH3N - Live Network Packet Sniffer (Reverse Engineering)")
    print("-" * 50)
    start_sniffer()