import socket
import struct
import threading
from scapy.all import *
from scapy.layers.inet import UDP, IP
import time

MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
PAYLOAD_TYPE = 0x4
BUFFER_SIZE = 1024

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
WHITE = "\033[97m"

def is_valid_broadcast(packet):
    try:
        if UDP in packet and Raw in packet:
            data = packet[Raw].load
            magic_cookie, message_type, udp_port, tcp_port = struct.unpack("!I B H H", data)
            if magic_cookie == MAGIC_COOKIE and message_type == MESSAGE_TYPE_OFFER:
                return packet[IP].src, udp_port, tcp_port
    except Exception as e:
        return None
    return None

def Looking_for_packets(timeout=10):
    print(f"{CYAN}Looking for packets that are broadcast...{RESET}")
    detected_info = {}

    # Use a simple for-loop to sniff packets for the given timeout
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Sniff a packet with timeout set by the loop
            packet = sniff(filter="udp", timeout=timeout, count=1)
            if not packet:
                continue

            # Process each sniffed packet
            for pkt in packet:
                result = is_valid_broadcast(pkt)
                if result:
                    ip, udp_port, tcp_port = result
                    print(f"{GREEN}Received offer from {ip} (UDP Port={udp_port}, TCP Port={tcp_port}){RESET}")
                    detected_info = {"ip": ip, "udp_port": udp_port, "tcp_port": tcp_port}
                    break  # Break if valid broadcast is detected
        except Exception as e:
            print(f"{RED}[Packet Sniffing Error] {e}{RESET}")

    # Return detected information or None if not detected
    return detected_info if detected_info else None


def handle_tcp_connection(server_ip, tcp_port, connection_id, file_size):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            # Disable Nagle's Algorithm for faster transmission
            tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Set larger buffer sizes for faster data transfer
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * BUFFER_SIZE)
            tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10 * BUFFER_SIZE)

            tcp_socket.connect((server_ip, tcp_port))
            print(f"{CYAN}[TCP {connection_id}] Connected to {server_ip}:{tcp_port}{RESET}")

            tcp_socket.sendall(f"{file_size}\n".encode())

            start_time = time.time()
            received_bytes = 0

            # Read data in larger chunks (BUFFER_SIZE)
            while received_bytes < file_size:
                data = tcp_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                received_bytes += len(data)

            end_time = time.time()

            duration = end_time - start_time
            speed = received_bytes * 8 / duration / 1e6  # Speed in bits/second

            # Updated print statement
            print(
                f"{GREEN}TCP transfer #{connection_id} finished, "
                f"total time: {duration:.2f} seconds, "
                f"total speed: {speed:.2f} bits/second{RESET}"
            )
    except Exception as e:
        print(f"{RED}[TCP {connection_id}] Error: {e}{RESET}")

# Updated UDP Handler with alternative structure
def handle_udp_connection(server_ip, udp_port, connection_id, file_size):
    udp_socket = None
    received_segments = set()
    try:
        # Create the UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * BUFFER_SIZE)  # Increase buffer size
        udp_socket.settimeout(3)

        # Prepare and send request
        request_packet = struct.pack("!IbQ", MAGIC_COOKIE, MESSAGE_TYPE_REQUEST, file_size)
        udp_socket.sendto(request_packet, (server_ip, udp_port))
        print(f"{YELLOW}[UDP {connection_id}] Request sent to {server_ip}:{udp_port}{RESET}")

        total_segments_expected = (file_size + BUFFER_SIZE - 1) // BUFFER_SIZE
        start_time = time.time()

        # Handle received data
        while len(received_segments) < total_segments_expected:
            try:
                data, _ = udp_socket.recvfrom(BUFFER_SIZE + 20)
                if len(data) >= 21:
                    cookie, msg_type, total_segments, segment_num = struct.unpack("!IbQQ", data[:21])
                    if cookie == MAGIC_COOKIE and msg_type == PAYLOAD_TYPE:
                        received_segments.add(segment_num)
            except socket.timeout:
                break

        # Calculate transfer stats
        end_time = time.time()
        duration = end_time - start_time
        packets_received = len(received_segments)
        packet_loss = 100 - (packets_received / total_segments_expected * 100)  # Loss in percentage
        speed = packets_received * BUFFER_SIZE * 8 / duration / 1e6  # Speed in bits/second

        # Output transfer summary
        print(
            f"{BLUE}UDP transfer #{connection_id} finished, "
            f"total time: {duration:.2f} seconds, "
            f"total speed: {speed:.2f} bits/second, "
            f"percentage of packets received successfully: {100 - packet_loss:.2f}%{RESET}"
        )
    except socket.timeout:
        print(f"{RED}[UDP {connection_id}] Timeout occurred while waiting for packets{RESET}")
    except socket.error as e:
        print(f"{RED}[UDP {connection_id}] Socket error: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[UDP {connection_id}] Error: {e}{RESET}")
    finally:
        if udp_socket:
            udp_socket.close()


def main():
    file_size = int(input("Enter the file size (in bytes): "))
    num_tcp_connections = int(input("Enter the number of TCP connections: "))
    num_udp_connections = int(input("Enter the number of UDP connections: "))

    while True:
        info = Looking_for_packets()
        if info is None:
            continue
        ip = info["ip"]
        udp_port = info["udp_port"]
        tcp_port = info["tcp_port"]

        print(f"{CYAN}Connecting to server at {ip} (TCP port: {tcp_port}, UDP port: {udp_port}){RESET}")

        tcp_threads = []
        for i in range(num_tcp_connections):
            thread = threading.Thread(target=handle_tcp_connection, args=(ip, tcp_port, i + 1, file_size))
            thread.start()
            tcp_threads.append(thread)

        udp_threads = []
        for i in range(num_udp_connections):
            thread = threading.Thread(target=handle_udp_connection, args=(ip, udp_port, i + 1, file_size))
            thread.start()
            udp_threads.append(thread)

        for thread in tcp_threads + udp_threads:
            thread.join()

        print(f"{CYAN}All transfers complete. Listening for offers...{RESET}\n")

if __name__ == "__main__":
    main()
