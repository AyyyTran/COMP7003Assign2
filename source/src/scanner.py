from scapy.all import sniff
import argparse
import sys
import os

# My utility functions and test case validation functions

def to_hex(value):
    return hex(value)

def to_binary(value, length=8):
    return bin(value)[2:].zfill(length)

def validate_interface(interface):
    if not interface.strip():  
        print("Error: The network interface cannot be an empty string.")
        sys.exit(1)

    try:
        with open(f"/sys/class/net/{interface}/operstate") as f:
            state = f.read().strip()
            if state != 'up':
                print(f"Warning: The interface '{interface}' is not active or is down.")
    except FileNotFoundError:
        print(f"Error: The network interface '{interface}' does not exist.")
        sys.exit(1)

def validate_filter(capture_filter):
    valid_filters = ['tcp', 'udp', 'arp', 'ip']
    if capture_filter not in valid_filters:
        print(f"Error: Invalid BPF filter '{capture_filter}'. Supported filters: {', '.join(valid_filters)}")
        sys.exit(1)

def validate_count(count):
    max_count=100
    if count <= 0:
        print("Error: The packet count must be a positive, non-zero integer.")
        sys.exit(1)
    if count > max_count:
        print(f"Error: The packet count exceeds the maximum allowed limit of {max_count}.")
        sys.exit(1)


def validate_arguments(expected_args):
    # known_args are the expected argument flags like --interface, --filter, --count
    known_args = expected_args

    # Check for too many arguments (beyond the expected number)
    if len(sys.argv) > (len(known_args) * 2) + 1:  # Each argument has a flag and a value
        print(f"Error: Too many arguments. Expected {len(known_args)} arguments.")
        sys.exit(1)

    # Check for any unknown arguments (arguments that aren't in the expected list)
    for arg in sys.argv[1:]:
        if arg.startswith('--') and arg.split('=')[0] not in known_args:
            print(f"Error: Unrecognized argument '{arg}'.")
            sys.exit(1)




# core logic functions 

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC (Hex): {dest_mac_readable}")
    print(f"Source MAC (Hex): {source_mac_readable}")
    print(f"EtherType (Hex): {ether_type}")
    return ether_type

# ARP Header Parsing
def parse_arp_header(hex_data):
    if len(hex_data) < 56:
        print(f"Error: ARP packet is too short. Expected at least 28 bytes.")
        return

    hardware_type = int(hex_data[28:32], 16)
    protocol_type = int(hex_data[32:36], 16)
    hardware_size = int(hex_data[36:38], 16)
    protocol_size = int(hex_data[38:40], 16)
    opcode = int(hex_data[40:44], 16)
    
    sender_mac = hex_data[44:56]
    sender_ip = hex_data[56:64]
    target_mac = hex_data[64:76]
    target_ip = hex_data[76:84]

    sender_mac_readable = ':'.join(sender_mac[i:i+2] for i in range(0, 12, 2))
    target_mac_readable = ':'.join(target_mac[i:i+2] for i in range(0, 12, 2))
    sender_ip_readable = '.'.join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))
    target_ip_readable = '.'.join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))

    print(f"Hardware Type: {hardware_type} (Decimal), {to_hex(hardware_type)} (Hex)")
    print(f"Protocol Type: {protocol_type} (Decimal), {to_hex(protocol_type)} (Hex)")
    print(f"Hardware Size: {hardware_size} (Decimal), {to_hex(hardware_size)} (Hex)")
    print(f"Protocol Size: {protocol_size} (Decimal), {to_hex(protocol_size)} (Hex)")
    print(f"Opcode: {opcode} (Decimal), {to_hex(opcode)} (Hex)")
    print(f"Sender MAC: {sender_mac_readable}")
    print(f"Sender IP: {sender_ip_readable}")
    print(f"Target MAC: {target_mac_readable}")
    print(f"Target IP: {target_ip_readable}")


# IPv4 Header Parsing
def parse_ipv4_header(hex_data):
    if len(hex_data) < 40:  
        print(f"Error: IPv4 packet is too short. Expected at least 20 bytes.")
        return

    version_ihl = int(hex_data[28:30], 16)
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    tos = int(hex_data[30:32], 16)
    total_length = int(hex_data[32:36], 16)
    identification = int(hex_data[36:40], 16)
    flags_fragment = int(hex_data[40:44], 16)
    ttl = int(hex_data[44:46], 16)
    protocol = int(hex_data[46:48], 16)
    header_checksum = int(hex_data[48:52], 16)
    
    src_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(52, 60, 2))
    dst_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(60, 68, 2))

    flags = flags_fragment >> 13
    fragment_offset = flags_fragment & 0x1FFF

    print(f"Version: {version}")
    print(f"IHL (Header Length): {ihl * 4} bytes")
    print(f"Type of Service: {tos}")
    print(f"Total Length: {total_length} (Decimal), {to_hex(total_length)} (Hex)")
    print(f"Identification: {identification} (Decimal), {to_hex(identification)} (Hex)")
    print(f"Flags: {to_binary(flags, 3)} (Binary)")
    print(f"Fragment Offset: {fragment_offset} (Decimal), {to_hex(fragment_offset)} (Hex)")
    print(f"Time to Live (TTL): {ttl} (Decimal), {to_hex(ttl)} (Hex)")
    print(f"Protocol: {protocol} (Decimal), {to_hex(protocol)} (Hex), {to_binary(protocol)} (Binary)")
    print(f"Header Checksum: {to_hex(header_checksum)}")
    print(f"Source IP (Hex): {src_ip}")
    print(f"Destination IP (Hex): {dst_ip}")

# TCP Header Parsing
def parse_tcp_header(hex_data):
    if len(hex_data) < 94:  
        print(f"Error: TCP packet is too short. Expected at least 20 bytes.")
        return

    src_port = int(hex_data[68:72], 16)
    dst_port = int(hex_data[72:76], 16)
    sequence_number = int(hex_data[76:84], 16)
    ack_number = int(hex_data[84:92], 16)
    flags = int(hex_data[92:94], 16)

    print(f"Source Port: {src_port} (Decimal), {to_hex(src_port)} (Hex)")
    print(f"Destination Port: {dst_port} (Decimal), {to_hex(dst_port)} (Hex)")
    print(f"Sequence Number: {sequence_number} (Decimal), {to_hex(sequence_number)} (Hex)")
    print(f"Acknowledgment Number: {ack_number} (Decimal), {to_hex(ack_number)} (Hex)")
    print(f"Flags: {to_binary(flags, 8)} (Binary)")

# UDP Header Parsing
def parse_udp_header(hex_data):
    if len(hex_data) < 84:  
        print(f"Error: UDP packet is too short. Expected at least 8 bytes.")
        return

    src_port = int(hex_data[68:72], 16)
    dst_port = int(hex_data[72:76], 16)
    length = int(hex_data[76:80], 16)
    checksum = int(hex_data[80:84], 16)

    print(f"Source Port: {src_port} (Decimal), {to_hex(src_port)} (Hex)")
    print(f"Destination Port: {dst_port} (Decimal), {to_hex(dst_port)} (Hex)")
    print(f"Length: {length} (Decimal), {to_hex(length)} (Hex)")
    print(f"Checksum: {checksum} (Decimal), {to_hex(checksum)} (Hex)")

# Function to handle each captured packet
def packet_callback(packet):
    if not packet:
        print("Error: Received an empty or null packet.")
        return

    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    # Process the Ethernet header
    print("\n" + "-"*50)
    print(f"Captured Packet (Hex): {hex_data}")
    ether_type = parse_ethernet_header(hex_data)

    # ARP  
    if ether_type == '0806':  
        parse_arp_header(hex_data)
    # IPv4  
    elif ether_type == '0800':  
        parse_ipv4_header(hex_data)
        protocol = hex_data[46:48]  
        # TCP 
        if protocol == '06':  
            parse_tcp_header(hex_data)
        # UDP 
        elif protocol == '11':  
            parse_udp_header(hex_data)
    else:
        # ANy Unsupported EtherType 
        print(f"Error: Unsupported EtherType {ether_type} (Hex). Valid EtherTypes: ipv4, UDP, TCP, ARP.")
    
    print("-"*50 + "\n")


# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)


if __name__ == "__main__":

    expected_args = ['--interface', '--filter', '--count']
    validate_arguments(expected_args)

    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--interface', required=True, help='Network interface to sniff packets')
    parser.add_argument('--filter', required=True, help='BPF filter for packet capture (e.g., arp, tcp, udp)')
    parser.add_argument('--count', required=True, type=int, help='Number of packets to capture')

    args = parser.parse_args()

    validate_interface(args.interface)
    validate_filter(args.filter)
    validate_count(args.count)

    capture_packets(args.interface, args.filter, args.count)