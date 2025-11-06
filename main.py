import socket
import struct
import mesh_pb2
import json
import time
import os
import logging
from datetime import datetime

# Configuration
MCAST_GRP = '224.0.0.69'    # Destination of the multicast packets
MCAST_PORT = 4403           # Deafault port for meshtastic UDP packets
IFACE_IP = '0.0.0.0'  # Replace with your PC network interface IP

# Base directories
BASE_DIR = 'packet_logs'
LOG_DIR = 'logs'

# Setup log directory
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logger
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
log_file = os.path.join(LOG_DIR, f'session_{timestamp}.txt')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()  # Keeps printing to terminal
    ]
)

logging.info(f"Listening for multicast UDP on {MCAST_GRP}:{MCAST_PORT} on interface {IFACE_IP}...")

# Setup UDP multicast socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))

# Join multicast group on specific interface
mreq = struct.pack('4s4s', socket.inet_aton(MCAST_GRP), socket.inet_aton(IFACE_IP))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

def ensure_directories(ip):
    ip_dir = os.path.join(BASE_DIR, ip.replace('.', '_'))
    os.makedirs(ip_dir, exist_ok=True)
    return ip_dir

def load_json(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            return []
    except Exception as e:
        logging.error(f"Error reading JSON file: {e}")
        return []

def save_to_json(packet_info, ip_dir):
    json_file = os.path.join(ip_dir, 'packets.json')
    data = load_json(json_file)
    data.append(packet_info)

    with open(json_file, 'w') as f:
        json.dump(data, f, indent=4)

def save_to_pcap(raw_data, ip_dir):
    pcap_file = os.path.join(ip_dir, 'packets.pcap')

    if not os.path.exists(pcap_file):
        with open(pcap_file, 'wb') as f:
            f.write(struct.pack('@ I H H i I I I',
                                0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # PCAP header

    ts_sec = int(time.time())
    ts_usec = int((time.time() % 1) * 1_000_000)
    incl_len = len(raw_data)
    orig_len = len(raw_data)

    pcap_header = struct.pack('@ I I I I', ts_sec, ts_usec, incl_len, orig_len)

    with open(pcap_file, 'ab') as f:
        f.write(pcap_header)
        f.write(raw_data)

def pretty_print(msg):
    f = getattr(msg, 'from')
    print(f"From: !{f:x}")
    print(f"To: !{msg.to:x}")

while True:
    try:
        data, addr = sock.recvfrom(1024)
        src_ip = addr[0]
        src_port = addr[1]
        logging.info(f"\nRaw UDP Packet from {addr}: {data}")

        ip_dir = ensure_directories(src_ip)

        # Save raw UDP packet to PCAP
        save_to_pcap(data, ip_dir)

        # Parse the incoming protobuf message
        msg = mesh_pb2.MeshPacket()
        msg.ParseFromString(data)

        # Prepare data to store in JSON
        packet_info = {
            "from": src_ip,
            "port": src_port,
            "decoded": str(msg)
        }

        # Save decoded info to JSON
        save_to_json(packet_info, ip_dir)

        logging.info(f"Decoded MeshPacket:\n{msg}")
        pretty_print(msg)

    except Exception as e:
        logging.error(f"Error decoding packet: {e}")
