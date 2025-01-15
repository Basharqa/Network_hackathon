import socket
import threading
import struct
import time
import netifaces

# Constants and configuration
MAGIC_COOKIE = 0xabcddcba
OFFER_MSG_TYPE = 0x2
REQUEST_MSG_TYPE = 0x3
PAYLOAD_MSG_TYPE = 0x4
MAX_BUFFER_SIZE = 1024

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
WHITE = "\033[97m"

# Dynamically retrieve network broadcast address
import netifaces

def fetch_broadcast_addresses():
    broadcast_addresses = []
    for iface in netifaces.interfaces():
        iface_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
        if iface_info:
            ip_info = iface_info[0]
            broadcast = ip_info.get('broadcast')
            if broadcast:
                broadcast_addresses.append(broadcast)
    return broadcast_addresses


# Handle TCP client communication (File transfer)
def process_tcp_connection(client_socket):
    with client_socket:
        try:
            print(f"{CYAN}[TCP] New client connected{RESET}")

            # Receive the file size
            data_received = b''
            data_end_found = False
            while not data_end_found:
                data_received += client_socket.recv(MAX_BUFFER_SIZE)
                if data_received.endswith(b'\n'):
                    data_end_found = True

            file_size = int(data_received.strip())
            print(f"{CYAN}[TCP] Preparing to send {file_size} bytes{RESET}")

            # Send the file in chunks
            sent_bytes = 0
            while sent_bytes < file_size:
                chunk_size = min(MAX_BUFFER_SIZE, file_size - sent_bytes)
                client_socket.sendall(b'A' * chunk_size)
                sent_bytes += chunk_size

            print(f"{GREEN}[TCP] File transfer completed successfully{RESET}")

        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"{RED}[TCP] Connection error: {e}{RESET}")

        except Exception as e:
            print(f"{RED}[TCP] Error during file transfer: {e}{RESET}")


# Handle UDP client requests (File transfer over UDP)
def process_udp_request(udp_socket, addr, file_size):
    try:
        print(f"{CYAN}[UDP] Processing request from {addr}{RESET}")

        # Increase buffer size for UDP sockets
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)  # Increase receive buffer size
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)  # Increase send buffer size

        # Calculate total number of packets to be sent
        total_packets = (file_size + MAX_BUFFER_SIZE - 1) // MAX_BUFFER_SIZE
        payload_size = 1022  # Payload size per packet
        #this the max number i can use to avoid the error winerror 10040

        for packet_num in range(total_packets):
            # Pack the header with magic cookie, message type, total packets, and packet number
            payload = struct.pack('!IbQQ', MAGIC_COOKIE, PAYLOAD_MSG_TYPE, total_packets, packet_num)

            # Append the payload data ('A' * payload_size)
            payload += b'A' * payload_size

            # Send the packet
            udp_socket.sendto(payload, addr)

        print(f"{GREEN}[UDP] Transfer to {addr} completed successfully{RESET}")

    except socket.timeout:
        print(f"{RED}[UDP] Request timed out with {addr}{RESET}")

    except Exception as e:
        print(f"{RED}[UDP] Error handling UDP request: {e}{RESET}")


# UDP request handler
def listen_for_udp_requests(udp_socket):
    print(f"{CYAN}[UDP] Server listening for requests{RESET}")

    # Use a flag to control the loop
    listening = True
    while listening:
        try:
            # Wait for a message from a client
            message, client_addr = udp_socket.recvfrom(MAX_BUFFER_SIZE)

            # Check if the message is valid and meets the required size
            if len(message) < 13:
                continue  # Skip processing if the message is too short

            # Unpack the message header
            magic_cookie, msg_type, file_size = struct.unpack('!IbQ', message[:13])

            # Use a switch-like structure with if-elif-else for message validation
            if magic_cookie != MAGIC_COOKIE:
                print(f"{RED}[UDP] Invalid magic cookie received{RESET}")
                continue  # Skip further processing

            if msg_type != REQUEST_MSG_TYPE:
                print(f"{RED}[UDP] Invalid message type received{RESET}")
                continue  # Skip further processing

            # If validation passes, spawn a new thread to handle the request
            threading.Thread(target=process_udp_request, args=(udp_socket, client_addr, file_size), daemon=True).start()

        except ConnectionResetError:
            print(f"{RED}[UDP] Connection reset by peer{RESET}")
            break  # Break the loop if connection is reset

        except socket.timeout:
            # If a socket timeout occurs, break out of the loop after retrying
            print(f"{YELLOW}[UDP] Socket timeout while waiting for requests{RESET}")
            listening = False  # Set flag to False to exit the loop

        except Exception as e:
            # Catch any unexpected exceptions
            print(f"{RED}[UDP] Error: {e}{RESET}")
            listening = False  # Exit the loop on any error


# Broadcast offers to network via UDP
def broadcast_udp_offers(udp_port, tcp_port, broadcast_port):
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_addresses = fetch_broadcast_addresses()
    while True:
        for address in broadcast_addresses:
            offer_payload = struct.pack("!I B H H", MAGIC_COOKIE, OFFER_MSG_TYPE, udp_port, tcp_port)
            broadcast_socket.sendto(offer_payload, (address, broadcast_port))
        print(f"{YELLOW}[UDP] Broadcast offer sent to network{RESET}")
        time.sleep(1)

def start_tcp_server():
    # TCP Server Setup
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.bind(("0.0.0.0", 0))
    tcp_port = tcp_server_socket.getsockname()[1]
    tcp_server_socket.listen(5)
    print(f"{CYAN}[TCP] Listening on port {tcp_port}{RESET}")

    # Handle incoming TCP connections
    threading.Thread(target=handle_tcp_connections, args=(tcp_server_socket,), daemon=True).start()
    return tcp_port  # Return the TCP port for the UDP server to use


def handle_tcp_connections(tcp_server_socket):
    while True:
        try:
            client_socket, client_addr = tcp_server_socket.accept()
            print(f"{CYAN}[TCP] New connection from {client_addr}{RESET}")
            threading.Thread(target=process_tcp_connection, args=(client_socket,), daemon=True).start()
        except Exception as e:
            print(f"{RED}[TCP] Error: {e}{RESET}")


def start_udp_server(tcp_port):
    # UDP Server Setup
    udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server_socket.bind(("0.0.0.0", 0))
    udp_port = udp_server_socket.getsockname()[1]
    print(f"{CYAN}[UDP] Listening on port {udp_port}{RESET}")

    # Broadcast Server Setup
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(("0.0.0.0", 0))
    broadcast_port = broadcast_socket.getsockname()[1]
    print(f"{CYAN}[Broadcast] on port {broadcast_port}{RESET}")

    # Start UDP request listener and UDP broadcast sender threads
    try:
        threading.Thread(target=listen_for_udp_requests, args=(udp_server_socket,), daemon=True).start()
        threading.Thread(target=broadcast_udp_offers, args=(udp_port, tcp_port, broadcast_port), daemon=True).start()
    except Exception as e:
        print(f"{RED}[UDP] Error setting up threads: {e}{RESET}")


def start_servers():
    # Start the TCP server and get the TCP port
    tcp_port = start_tcp_server()
    # Start the UDP server, passing the TCP port
    start_udp_server(tcp_port)

    # Keep the main thread running
    try:
        while True:
            time.sleep(1)  # Prevent the main thread from exiting
    except KeyboardInterrupt:
        print(f"{YELLOW}[Server] Shutting down...{RESET}")


if __name__ == "__main__":
    start_servers()

