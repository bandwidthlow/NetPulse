#!/usr/bin/env python3
import os
import random
import subprocess
import sys
import signal
from colorama import Fore, Style
from scapy.all import sniff, wrpcap, IP

class NetworkAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_count = {}
        self.captured_packets = []
        self.save_file = None  # Save file name to be used on exit

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def random_color(self):
        return random.choice([Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN])

    def print_colored_banner(self):
        try:
            result = subprocess.run(["toilet", "-f", "big", "bandwidthlow"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{self.random_color()}{result.stdout}{Style.RESET_ALL}")
            else:
                print(self.random_color() + "bandwidthlow" + Style.RESET_ALL)
        except FileNotFoundError:
            print(Fore.RED + "'toilet' command not found. Please install or use the fallback banner." + Style.RESET_ALL)
            print(self.random_color() + "bandwidthlow" + Style.RESET_ALL)

    def print_tool_details(self):
        details = [
            Fore.GREEN + '📡 Network Traffic Analyzer Tool' + Style.RESET_ALL,
            Fore.YELLOW + '====================================' + Style.RESET_ALL,
            Fore.CYAN + 'Welcome to the basic version of our Network Traffic Analyzer tool! 🚀' + Style.RESET_ALL,
            Fore.BLUE + 'This tool captures network traffic, analyzes packets, and provides insights. 🔍' + Style.RESET_ALL,
            Fore.MAGENTA + '⚠️ Please note: This is a basic version, a GUI is currently in development!' + Style.RESET_ALL,
            Fore.RED + '====================================' + Style.RESET_ALL,
            Fore.YELLOW + '👨‍💻 Features include:' + Style.RESET_ALL,
            Fore.CYAN + '  ✅ Real-time packet capture and analysis' + Style.RESET_ALL,
            Fore.CYAN + '  ✅ Protocol tracking' + Style.RESET_ALL,
            Fore.CYAN + '  ✅ Saving captured packets to a .pcap file' + Style.RESET_ALL,
            Fore.GREEN + '📍 We hope you enjoy using it! Stay tuned for more updates!' + Style.RESET_ALL
        ]
        for line in details:
            print(line)

    def validate_interface(self, interface):
        available_interfaces = os.listdir('/sys/class/net/')
        if interface not in available_interfaces:
            print(Fore.RED + f"Error: Interface {interface} not found." + Style.RESET_ALL)
            return False
        return True

    def capture_traffic(self, interface, protocol_filter):
        print(Fore.CYAN + "Capturing traffic on interface:", interface, Style.RESET_ALL)
        filter_str = protocol_filter.lower() if protocol_filter else "ip"

        try:
            sniff(iface=interface, prn=self.analyze_packet, filter=filter_str, store=True)
        except KeyboardInterrupt:
            print(Fore.RED + "\nStopping capture..." + Style.RESET_ALL)
            self.save_captured_packets()

    def analyze_packet(self, packet):
        self.packet_count += 1
        self.captured_packets.append(packet)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            # Track protocol count for summary
            if proto not in self.protocol_count:
                self.protocol_count[proto] = 0
            self.protocol_count[proto] += 1
            
            # Print detailed output
            print(Fore.GREEN + f"Packet {self.packet_count}: Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}" + Style.RESET_ALL)

            # Print raw packet details for additional insight
            print(Fore.BLUE + f"Packet captured: {packet.summary()}" + Style.RESET_ALL)

    def save_captured_packets(self):
        if self.save_file:
            wrpcap(self.save_file, self.captured_packets)
            print(Fore.GREEN + f"Packets saved to {self.save_file}" + Style.RESET_ALL)
        self.print_stats()

    def print_stats(self):
        print(Fore.CYAN + "\nCapture Summary:" + Style.RESET_ALL)
        print(Fore.YELLOW + f"Total Packets Captured: {self.packet_count}" + Style.RESET_ALL)
        for proto, count in self.protocol_count.items():
            print(Fore.YELLOW + f"Protocol {proto}: {count} packets" + Style.RESET_ALL)

    def signal_handler(self, sig, frame):
        print(Fore.RED + "\nStopping capture..." + Style.RESET_ALL)
        self.save_captured_packets()
        sys.exit(0)

    def main(self):
        self.clear_screen()
        self.print_colored_banner()  
        self.print_tool_details()

        interface = input(Fore.YELLOW + "🌐 Enter the interface to capture traffic (e.g., eth0): " + Style.RESET_ALL)
        if not self.validate_interface(interface):
            return

        protocol_filter = input(Fore.YELLOW + "🔧 Enter protocol filter (e.g., tcp, udp, icmp or leave empty for all): " + Style.RESET_ALL)
        self.save_file = input(Fore.YELLOW + "💾 Enter file name to save captured packets (e.g., traffic.pcap or leave empty): " + Style.RESET_ALL)

        if self.save_file == "":
            self.save_file = None

        signal.signal(signal.SIGINT, self.signal_handler)

        try:
            self.capture_traffic(interface, protocol_filter)
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    analyzer = NetworkAnalyzer()
    analyzer.main()
