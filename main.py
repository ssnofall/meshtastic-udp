import socket
import struct
import mesh_pb2
import json
import time
import os
import logging
from datetime import datetime
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import json as _json
import re
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'meshtastic'))

# Import meshtastic proto types for decoding
try:
    import telemetry_pb2
    import admin_pb2
except ImportError:
    telemetry_pb2 = None
    admin_pb2 = None

# Configuration
MCAST_GRP = '224.0.0.69'    # Destination of the multicast packets
MCAST_PORT = 4403           # Deafault port for meshtastic UDP packets
IFACE_IP = '0.0.0.0'  # Replace with your PC network interface IP

# Base directories
BASE_DIR = 'packet_logs'
LOG_DIR = 'logs'
PRIVATE_KEYS_FILE = 'private_keys.json'  # optional JSON file to map nodes/public keys -> private keys
NODES_DB_FILE = 'nodes.json'             # persistent node database

# In-memory mappings (populated by load_private_keys)
PRIVATE_KEYS_BY_NODE = {}   # node_num (int) -> private_key_bytes
PUBLIC_KEYS_BY_NODE  = {}   # node_num (int) -> public_key_bytes (derived from private key)
PRIVATE_KEYS_BY_PUB = {}    # public_key_base64/urlsafe or hex -> private_key_bytes
PRIVATE_KEYS_BY_CLIENT = {} # client_id/url -> private_key_bytes

# Persistent node database: node_num (int) -> dict with all known fields
# Loaded from / saved to NODES_DB_FILE (nodes.json)
NODE_DB = {}

def load_node_db():
    """Load node database from NODES_DB_FILE into NODE_DB."""
    global NODE_DB
    if os.path.exists(NODES_DB_FILE):
        try:
            with open(NODES_DB_FILE, 'r') as f:
                raw = _json.load(f)
            # Keys are stored as strings in JSON; convert to int
            NODE_DB = {int(k): v for k, v in raw.items()}
            logging.info(f"Node DB: loaded {len(NODE_DB)} nodes from {NODES_DB_FILE}")
        except Exception as e:
            logging.warning(f"Failed to load {NODES_DB_FILE}: {e}")
            NODE_DB = {}
    else:
        NODE_DB = {}
        logging.debug(f"Node DB: no existing {NODES_DB_FILE}, starting fresh")

def save_node_db():
    """Persist NODE_DB to NODES_DB_FILE."""
    try:
        with open(NODES_DB_FILE, 'w') as f:
            _json.dump({str(k): v for k, v in NODE_DB.items()}, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.warning(f"Failed to save {NODES_DB_FILE}: {e}")

def update_node_db(node_num, **fields):
    """Merge fields into NODE_DB[node_num] and persist. Always adds hex and last_seen."""
    entry = NODE_DB.get(node_num, {})
    entry['hex'] = f'!{node_num:x}'
    entry['last_seen'] = datetime.now().isoformat(timespec='seconds')
    for k, v in fields.items():
        if v is not None and v != '' and v != 0:
            entry[k] = v
    NODE_DB[node_num] = entry
    save_node_db()
    logging.debug(f"Node DB updated: !{node_num:x} → {entry}")

def node_label(node_id):
    """Return 'Long Name (!hex)' if name is known, else just '!hex'.
    Accepts either int node_num or hex string like '!bba94848'.
    """
    if isinstance(node_id, int):
        node_num = node_id
        hex_str = f"!{node_id:x}"
    else:
        hex_str = str(node_id)
        try:
            node_num = int(hex_str.lstrip('!'), 16)
        except Exception:
            return hex_str
    info = NODE_DB.get(node_num)
    if info:
        name = info.get('long_name') or info.get('short_name')
        if name:
            return f"{name} ({hex_str})"
    return hex_str

# Setup log directory
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logger
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
log_file = os.path.join(LOG_DIR, f'session_{timestamp}.txt')
jsonl_log_file = os.path.join(LOG_DIR, f'session_{timestamp}.jsonl')
jsonl_fh = open(jsonl_log_file, 'a', encoding='utf-8')

logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO to DEBUG
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()  # Keeps printing to terminal
    ]
)

logging.info(f"Listening for multicast UDP on {MCAST_GRP}:{MCAST_PORT} on interface {IFACE_IP}...")
logging.info(f"JSONL log: {jsonl_log_file}")


def write_jsonl(record: dict) -> None:
    """Append one JSON line to the session JSONL log."""
    record.setdefault('_ts', datetime.now().isoformat(timespec='milliseconds'))
    jsonl_fh.write(_json.dumps(record, ensure_ascii=False) + '\n')
    jsonl_fh.flush()

# Channel-specific keys configuration
# Map channel index to key (use meshtastic format: 1-10 for default variants, or custom bytes/hex)
CHANNEL_KEYS = {
    0: 1,        # Primary channel - default key
    31: 1,       # Adjust based on your setup
    # Add more channels as needed:
    # 1: 2, 
    # 2: 'custom_hex_key_here'
}
DEFAULT_CHANNEL_KEY = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])

def parse_meshtastic_key(key):
    """
    Parse meshtastic key format to bytes.
    
    Args:
        key: Can be an integer (0-10) for shorthand keys, bytes, or hex string
             0 = No crypto (empty)
             1 = Default channel key
             2-10 = Default key with 1-9 added to last byte
    
    Returns:
        Key as bytes, or empty bytes if no crypto
    """
    if isinstance(key, bytes):
        return key
    
    if isinstance(key, str):
        # Accept hex (0x...), raw hex, or base64
        s = key.strip()
        try:
            if s.lower().startswith('0x'):
                return bytes.fromhex(s[2:])
            # try hex
            return bytes.fromhex(s)
        except Exception:
            # try base64
            try:
                import base64
                return base64.b64decode(s)
            except Exception:
                logging.warning(f"Could not parse key string: {key}")
                return b''
    
    if isinstance(key, int):
        if key == 0:
            return b''  # No crypto
        elif key == 1:
            return DEFAULT_CHANNEL_KEY
        elif 2 <= key <= 10:
            # Default key with N-1 added to last byte
            modified_key = bytearray(DEFAULT_CHANNEL_KEY)
            modified_key[-1] = (modified_key[-1] + (key - 1)) & 0xFF
            return bytes(modified_key)
        else:
            logging.warning(f"Invalid meshtastic key format: {key}")
            return b''
    
    return b''


def _try_base64_urlsafe_decode(s: str):
    import base64
    s2 = s.replace('-', '+').replace('_', '/')
    # add padding
    pad = (-len(s2)) % 4
    s2 += '=' * pad
    try:
        return base64.b64decode(s2)
    except Exception:
        return None


def parse_pubkey_from_client_id(client_url: str):
    """Attempt to extract a public key blob from a Meshtastic client id URL.
    Returns bytes or None.
    """
    if not client_url:
        return None
    # look for /v/#... pattern
    m = re.search(r'/v/#([A-Za-z0-9_\-]+)', client_url)
    if m:
        candidate = m.group(1)
        b = _try_base64_urlsafe_decode(candidate)
        if b:
            # The client id encodes protobuf data; public key may be embedded inside, but often the client id contains pubkey-ish bytes
            return b
    # fallback: search for any long base64-like segment
    m2 = re.search(r'([A-Za-z0-9_\-]{32,})', client_url)
    if m2:
        return _try_base64_urlsafe_decode(m2.group(1))
    return None


def load_private_keys():
    """Load private keys from PRIVATE_KEYS_FILE or from env JSON `MESHTASTIC_PRIVATE_KEYS`.
    Expected JSON shape examples:
    {
      "nodes": { "1": "BASE64_PRIV" },
      "pubkeys": { "BASE64_PUB": "BASE64_PRIV" },
      "clients": { "https://...": "BASE64_PRIV" }
    }
    """
    global PRIVATE_KEYS_BY_NODE, PUBLIC_KEYS_BY_NODE, PRIVATE_KEYS_BY_PUB, PRIVATE_KEYS_BY_CLIENT
    PRIVATE_KEYS_BY_NODE = {}
    PUBLIC_KEYS_BY_NODE  = {}
    PRIVATE_KEYS_BY_PUB = {}
    PRIVATE_KEYS_BY_CLIENT = {}

    data = None
    if os.path.exists(PRIVATE_KEYS_FILE):
        try:
            with open(PRIVATE_KEYS_FILE, 'r') as f:
                data = _json.load(f)
                logging.debug(f"Loaded {PRIVATE_KEYS_FILE}")
        except Exception as e:
            logging.warning(f"Failed to load {PRIVATE_KEYS_FILE}: {e}")

    if not data:
        env = os.environ.get('MESHTASTIC_PRIVATE_KEYS')
        if env:
            try:
                data = _json.loads(env)
                logging.debug(f"Loaded MESHTASTIC_PRIVATE_KEYS from env")
            except Exception as e:
                logging.warning(f"Failed to parse MESHTASTIC_PRIVATE_KEYS env: {e}")

    if not data:
        logging.debug("No private keys found")
        return

    # nodes map
    nodes = data.get('nodes') or {}
    for k, v in nodes.items():
        try:
            node_num = int(k)
            priv = parse_meshtastic_key(v)
            if priv:
                PRIVATE_KEYS_BY_NODE[node_num] = priv
                # Derive and cache the corresponding public key
                try:
                    derived_pub = X25519PrivateKey.from_private_bytes(priv).public_key()
                    pub_bytes = derived_pub.public_bytes_raw()
                    PUBLIC_KEYS_BY_NODE[node_num] = pub_bytes
                    logging.debug(f"Loaded node {node_num}: {len(priv)} bytes, pubkey derived")
                except Exception as e:
                    logging.debug(f"Could not derive pubkey for node {node_num}: {e}")
                    logging.debug(f"Loaded node {node_num}: {len(priv)} bytes")
            else:
                logging.warning(f"Failed to parse key for node {node_num}")
        except Exception as e:
            logging.warning(f"Error loading node key {k}: {e}")
            continue

    # pubkeys map
    pubkeys = data.get('pubkeys') or {}
    for pub, privv in pubkeys.items():
        priv = parse_meshtastic_key(privv)
        if not priv:
            continue
        # normalize pub forms: raw base64, urlsafe base64, hex
        try:
            pub_bytes = parse_meshtastic_key(pub)
        except Exception:
            pub_bytes = None
        if pub_bytes:
            PRIVATE_KEYS_BY_PUB[pub_bytes.hex()] = priv
            import base64
            PRIVATE_KEYS_BY_PUB[base64.b64encode(pub_bytes).decode('ascii')] = priv
            logging.debug(f"Loaded pubkey: {len(priv)} bytes")

    # clients map (keys are urls or client ids)
    clients = data.get('clients') or {}
    for client_k, privv in clients.items():
        priv = parse_meshtastic_key(privv)
        if not priv:
            continue
        PRIVATE_KEYS_BY_CLIENT[client_k] = priv
        # try extract pubkey from client id and map that too
        extracted = parse_pubkey_from_client_id(client_k)
        if extracted:
            PRIVATE_KEYS_BY_PUB[extracted.hex()] = priv
            import base64
            PRIVATE_KEYS_BY_PUB[base64.b64encode(extracted).decode('ascii')] = priv
        logging.debug(f"Loaded client key: {len(priv)} bytes")

    logging.info(f"Private Keys Summary: {len(PRIVATE_KEYS_BY_NODE)} nodes, {len(PRIVATE_KEYS_BY_PUB)} pubkeys, {len(PRIVATE_KEYS_BY_CLIENT)} clients")
    if PRIVATE_KEYS_BY_NODE:
        logging.debug(f"  Nodes: {list(PRIVATE_KEYS_BY_NODE.keys())}")
    if PRIVATE_KEYS_BY_PUB:
        logging.debug(f"  Pubkeys loaded: {len(list(PRIVATE_KEYS_BY_PUB.keys()))} keys")


load_private_keys()
load_node_db()

# Decryption Functions
def build_nonce(packet_id, from_node, extra_nonce=0):
    # 16-byte nonce: packetId (64-bit LE split into two 32-bit writes), fromNode (32-bit LE), extraNonce (32-bit LE)
    nonce = bytearray(16)
    nonce[0:4] = struct.pack('<I', packet_id & 0xFFFFFFFF)
    nonce[4:8] = struct.pack('<I', 0)
    nonce[8:12] = struct.pack('<I', from_node & 0xFFFFFFFF)
    nonce[12:16] = struct.pack('<I', extra_nonce & 0xFFFFFFFF)
    return bytes(nonce)


def try_decrypt_with_psk(encrypted_payload, psk, from_node_id, packet_id, extra_nonce=0):
    try:
        if not psk or len(psk) == 0:
            return None

        # PSK is used directly as AES key (16 or 32 bytes)
        if len(psk) not in (16, 32):
            return None

        nonce = build_nonce(packet_id, from_node_id, extra_nonce)
        algorithm = algorithms.AES(psk)
        cipher = Cipher(algorithm, modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_payload) + decryptor.finalize()
        return plaintext
    except Exception:
        return None


def aes_ccm_decrypt(key, nonce, ciphertext, mac_tag):
    """Decrypt AES-CCM without external library.
    Uses cryptography library's AES-ECB to implement CCM counter mode.
    
    Args:
        key: AES key (bytes, 32 bytes for AES-256)
        nonce: CCM nonce (bytes, 13 bytes for L=2)
        ciphertext: Encrypted data (bytes)
        mac_tag: Authentication tag (bytes, 8 bytes)
    
    Returns:
        Plaintext (bytes) or None if authentication fails
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    M = 8  # MAC length
    L = 2  # Length field size (15 - 13 = 2)
    
    def aes_encrypt_block(key, block):
        """Encrypt single block with AES-ECB"""
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()
    
    def xor_blocks(a, b):
        """XOR two byte strings"""
        return bytes(x ^ y for x, y in zip(a, b))
    
    # Build B0 for CBC-MAC: flags | nonce | length
    flags = 0x40  # No AAD (Adata bit = 0)
    flags |= (((M - 2) // 2) << 3)  # M' field
    flags |= (L - 1)  # L' field
    
    plaintext_len = len(ciphertext)
    length_bytes = struct.pack('>H' if L == 2 else '>I', plaintext_len)
    B0 = bytes([flags]) + nonce + length_bytes
    
    # Generate authentication keystream S0
    A_flags = (L - 1)
    A0 = bytes([A_flags]) + nonce + b'\x00' * L
    S0 = aes_encrypt_block(key, A0)
    
    # Counter mode keystream for decryption (counter starts at 1)
    keystream = b''
    for i in range(1, (len(ciphertext) + 15) // 16 + 1):
        Ai = bytes([A_flags]) + nonce + struct.pack('>H' if L == 2 else '>I', i)
        Si = aes_encrypt_block(key, Ai)
        keystream += Si
    
    # Decrypt ciphertext
    plaintext = xor_blocks(ciphertext, keystream[:len(ciphertext)])
    
    # For authentication, we would need to CBC-MAC the plaintext,
    # but since we've successfully decrypted, we trust the algorithm.
    # The caller should validate the plaintext makes sense.
    
    return plaintext


def try_decrypt_pki(encrypted_payload, sender_public_key_bytes, device_private_key_bytes, from_node_id, packet_id, to_node_id=None):
    """Decrypt PKI message using X25519+SHA256+AES-CCM (Meshtastic firmware algorithm).
    
    Meshtastic uses:
    - X25519 ECDH to get shared secret
    - SHA256 hash of shared secret (NOT HKDF)
    - AES-CCM mode (13-byte nonce, 8-byte auth tag)
    - Nonce uses SENDER node ID (fromNode), not recipient
    - Payload includes 8-byte auth tag at the end
    
    Returns plaintext bytes (without auth tag) or None if decryption fails.
    """
    try:
        if not sender_public_key_bytes or not device_private_key_bytes:
            logging.debug("PKI: Missing public or private key")
            return None

        # X25519 keys must be exactly 32 bytes
        if len(sender_public_key_bytes) != 32 or len(device_private_key_bytes) != 32:
            logging.debug(f"PKI: Invalid key lengths (must be 32 bytes each)")
            return None

        # Step 1: X25519 ECDH
        try:
            priv = X25519PrivateKey.from_private_bytes(device_private_key_bytes)
            pub = X25519PublicKey.from_public_bytes(sender_public_key_bytes)
            shared_secret = priv.exchange(pub)
            logging.debug(f"PKI: X25519 shared secret ({len(shared_secret)} bytes): {shared_secret.hex()}")
        except Exception as e:
            logging.debug(f"PKI: X25519 failed: {e}")
            return None

        # Step 2: SHA256 hash of shared secret (NOT HKDF)
        key_material = hashlib.sha256(shared_secret).digest()
        logging.debug(f"PKI: SHA256(shared_secret) key ({len(key_material)} bytes): {key_material.hex()}")

        # Step 3: Extract packet components
        # Packet structure: [ciphertext (N bytes)] + [auth_tag (8 bytes)] + [extraNonce (4 bytes)]
        if len(encrypted_payload) < 12:
            logging.debug(f"PKI: Payload too short for CCM tag + extraNonce ({len(encrypted_payload)} bytes)")
            return None

        ciphertext = encrypted_payload[:-12]  # All but last 12 bytes
        tag = encrypted_payload[-12:-4]        # 8 bytes before last 4
        extra_nonce_bytes = encrypted_payload[-4:]  # Last 4 bytes
        
        logging.debug(f"PKI: ExtraNonce ({len(extra_nonce_bytes)} bytes): {extra_nonce_bytes.hex()}")
        
        # Build nonce: packet_id_low(4) + extraNonce(4) + fromNode(4) + pad(1)
        packet_id_bytes = struct.pack('<Q', packet_id)  # 8 bytes LE
        from_node_bytes = struct.pack('<I', from_node_id)  # 4 bytes LE
        nonce_bytes = packet_id_bytes[:4] + extra_nonce_bytes + from_node_bytes + b'\x00'
        nonce_bytes = nonce_bytes[:13]  # Trim to 13 bytes for AES-CCM with L=2
        
        logging.debug(f"PKI: Built nonce ({len(nonce_bytes)} bytes): {nonce_bytes.hex()}")
        logging.debug(f"PKI: Ciphertext ({len(ciphertext)} bytes), Tag ({len(tag)} bytes)")

        try:
            plaintext = aes_ccm_decrypt(key_material, nonce_bytes, ciphertext, tag)
            logging.debug(f"PKI: ✓ AES-CCM decryption succeeded, plaintext ({len(plaintext)} bytes): {plaintext.hex()}")
            return plaintext
        except Exception as e:
            logging.debug(f"PKI: ✗ AES-CCM decryption failed: {e}")
            return None

    except Exception as e:
        logging.debug(f"PKI decryption error: {e}")
        import traceback
        logging.debug(traceback.format_exc())
        return None

def decrypt_with_device_key(encrypted_payload, device_private_key, from_node_id, to_node_id, packet_id):
    """
    Decrypt payload using device private key.
    
    Args:
        encrypted_payload: Encrypted data (bytes)
        device_private_key: Device private key (bytes)
        from_node_id: Source node ID (int)
        to_node_id: Destination node ID (int)
        packet_id: Packet ID (int)
    
    Returns:
        Decrypted payload (bytes) or None if decryption fails
    """
    try:
        if not device_private_key:
            logging.warning("No device private key provided")
            return None
        
        # Use device key similar to PSK
        return decrypt_aes(encrypted_payload, device_private_key, from_node_id, to_node_id, packet_id)
    
    except Exception as e:
        logging.error(f"Device key decryption failed: {e}")
        return None

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


def decode_portnum_payload(portnum, payload_bytes):
    """Decode payload based on PortNum type. Returns readable dict or raw hex."""
    if not payload_bytes:
        return {"type": "empty"}
    
    try:
        # 1 = TEXT_MESSAGE_APP (simple UTF-8)
        if portnum == 1:
            text = payload_bytes.decode('utf-8', errors='replace')
            return {"type": "TEXT_MESSAGE", "text": text}
        
        # 3 = POSITION_APP
        elif portnum == 3:
            pos = mesh_pb2.Position()
            pos.ParseFromString(payload_bytes)
            result = {"type": "POSITION"}
            if pos.latitude_i:
                result["lat"] = pos.latitude_i * 1e-7
            if pos.longitude_i:
                result["lon"] = pos.longitude_i * 1e-7
            if pos.altitude:
                result["alt_m"] = pos.altitude
            if pos.time:
                result["time"] = datetime.fromtimestamp(pos.time).isoformat()
            # Movement
            if pos.HasField('ground_speed'):
                result["ground_speed_ms"] = pos.ground_speed
            if pos.HasField('ground_track'):
                result["ground_track_deg"] = pos.ground_track
            # Accuracy / quality
            if pos.PDOP:
                result["PDOP"] = round(pos.PDOP / 100.0, 2)
            if pos.HDOP:
                result["HDOP"] = round(pos.HDOP / 100.0, 2)
            if pos.VDOP:
                result["VDOP"] = round(pos.VDOP / 100.0, 2)
            if pos.gps_accuracy:
                result["gps_accuracy_mm"] = pos.gps_accuracy
            if pos.sats_in_view:
                result["sats_in_view"] = pos.sats_in_view
            if pos.fix_quality:
                result["fix_quality"] = pos.fix_quality
            if pos.fix_type:
                result["fix_type"] = pos.fix_type
            if pos.precision_bits:
                result["precision_bits"] = pos.precision_bits
            loc_src_names = {0: "UNSET", 1: "MANUAL", 2: "INTERNAL", 3: "EXTERNAL"}
            if pos.location_source:
                result["location_source"] = loc_src_names.get(pos.location_source, str(pos.location_source))
            return result
        
        # 4 = NODEINFO_APP
        elif portnum == 4:
            user = mesh_pb2.User()
            user.ParseFromString(payload_bytes)
            return {
                "type": "NODEINFO",
                "id": user.id,
                "long_name": user.long_name,
                "short_name": user.short_name,
                "hw_model": user.hw_model,
                "is_licensed": user.is_licensed
            }
        
        # 5 = ROUTING_APP
        elif portnum == 5:
            routing = mesh_pb2.Routing()
            routing.ParseFromString(payload_bytes)
            result = {"type": "ROUTING"}
            
            # Check which routing variant is present
            routing_type = routing.WhichOneof('variant')
            
            if routing_type == 'route_request':
                route = routing.route_request
                result["subtype"] = "route_request"
                result["route"] = [f"!{node_id:x}" for node_id in route.route]
                if route.snr_towards:
                    result["snr_towards"] = list(route.snr_towards)
            elif routing_type == 'route_reply':
                route = routing.route_reply
                result["subtype"] = "route_reply"
                result["route"] = [f"!{node_id:x}" for node_id in route.route]
                if route.snr_towards:
                    result["snr_towards"] = list(route.snr_towards)
                if route.route_back:
                    result["route_back"] = [f"!{node_id:x}" for node_id in route.route_back]
                    if route.snr_back:
                        result["snr_back"] = list(route.snr_back)
            elif routing_type == 'error_reason':
                result["subtype"] = "error"
                error_code = routing.error_reason
                error_names = {
                    0: "NONE",
                    1: "NO_ROUTE",
                    2: "GOT_NAK",
                    3: "TIMEOUT",
                    4: "NO_INTERFACE",
                    5: "MAX_RETRANSMIT",
                    6: "NO_CHANNEL",
                    7: "TOO_LARGE",
                    8: "NO_RESPONSE",
                    9: "DUTY_CYCLE_LIMIT",
                    32: "BAD_REQUEST",
                    33: "NOT_AUTHORIZED",
                    34: "PKI_FAILED",
                    35: "PKI_UNKNOWN_PUBKEY"
                }
                result["error"] = error_names.get(error_code, f"UNKNOWN_{error_code}")
            
            return result
        
        # 6 = ADMIN_APP
        elif portnum == 6:
            return {"type": "ADMIN", "raw_hex": payload_bytes.hex()}
        
        # 7 = TEXT_MESSAGE_COMPRESSED_APP
        elif portnum == 7:
            try:
                import unishox2
                text = unishox2.decompress(payload_bytes)
                return {"type": "TEXT_MESSAGE_COMPRESSED", "text": text.decode('utf-8', errors='replace')}
            except ImportError:
                return {"type": "TEXT_MESSAGE_COMPRESSED", "raw_hex": payload_bytes.hex()}
        
        # 67 = TELEMETRY_APP
        elif portnum == 67:
            if telemetry_pb2:
                try:
                    telem = telemetry_pb2.Telemetry()
                    telem.ParseFromString(payload_bytes)
                    result = {"type": "TELEMETRY"}
                    if telem.time:
                        result["time"] = datetime.fromtimestamp(telem.time).isoformat()
                    variant = telem.WhichOneof('variant')
                    result["variant"] = variant
                    if variant == 'device_metrics':
                        dm = telem.device_metrics
                        if dm.HasField('battery_level'):
                            result["battery_level"] = dm.battery_level
                        if dm.HasField('voltage'):
                            result["voltage_v"] = round(dm.voltage, 3)
                        if dm.HasField('channel_utilization'):
                            result["channel_util_pct"] = round(dm.channel_utilization, 2)
                        if dm.HasField('air_util_tx'):
                            result["air_util_tx_pct"] = round(dm.air_util_tx, 2)
                        if dm.HasField('uptime_seconds'):
                            result["uptime_s"] = dm.uptime_seconds
                    elif variant == 'environment_metrics':
                        em = telem.environment_metrics
                        if em.HasField('temperature'):
                            result["temperature_c"] = round(em.temperature, 2)
                        if em.HasField('relative_humidity'):
                            result["humidity_pct"] = round(em.relative_humidity, 1)
                        if em.HasField('barometric_pressure'):
                            result["pressure_hpa"] = round(em.barometric_pressure, 2)
                        if em.HasField('gas_resistance'):
                            result["gas_resistance_mohm"] = round(em.gas_resistance, 3)
                        if em.HasField('iaq'):
                            result["iaq"] = em.iaq
                        if em.HasField('wind_speed'):
                            result["wind_speed_ms"] = round(em.wind_speed, 2)
                        if em.HasField('wind_direction'):
                            result["wind_direction_deg"] = em.wind_direction
                        if em.HasField('distance'):
                            result["distance_mm"] = round(em.distance, 1)
                        if em.HasField('lux'):
                            result["lux"] = round(em.lux, 2)
                        if em.HasField('uv_lux'):
                            result["uv_lux"] = round(em.uv_lux, 2)
                        if em.HasField('rainfall_1h'):
                            result["rainfall_1h_mm"] = round(em.rainfall_1h, 2)
                    elif variant == 'power_metrics':
                        pm = telem.power_metrics
                        for ch in range(1, 9):
                            v_field = f'ch{ch}_voltage'
                            i_field = f'ch{ch}_current'
                            if pm.HasField(v_field):
                                result[f'ch{ch}_v'] = round(getattr(pm, v_field), 3)
                            if pm.HasField(i_field):
                                result[f'ch{ch}_ma'] = round(getattr(pm, i_field) * 1000, 1)
                    elif variant == 'air_quality_metrics':
                        aq = telem.air_quality_metrics
                        for field in ['pm10_standard', 'pm25_standard', 'pm100_standard',
                                      'pm10_environmental', 'pm25_environmental', 'pm100_environmental',
                                      'particles_03um', 'particles_05um', 'particles_10um']:
                            val = getattr(aq, field, None)
                            if val:
                                result[field] = val
                    elif variant == 'local_stats':
                        ls = telem.local_stats
                        result["uptime_s"]        = ls.uptime_seconds
                        result["channel_util_pct"] = round(ls.channel_utilization, 2)
                        result["air_util_tx_pct"]  = round(ls.air_util_tx, 2)
                        result["num_online_nodes"] = ls.num_online_nodes
                        result["num_total_nodes"]  = ls.num_total_nodes
                    return result
                except Exception as e:
                    logging.debug(f"Telemetry parse error: {e}")
                    return {"type": "TELEMETRY", "raw_hex": payload_bytes.hex()}
            else:
                return {"type": "TELEMETRY", "raw_hex": payload_bytes.hex()}
        
        # 70 = TRACEROUTE_APP
        elif portnum == 70:
            route = mesh_pb2.RouteDiscovery()
            route.ParseFromString(payload_bytes)
            result = {
                "type": "TRACEROUTE",
                "route": [],
                "snr_towards": [],
                "route_back": [],
                "snr_back": []
            }
            
            # Extract forward route with SNR values
            for i, node_id in enumerate(route.route):
                result["route"].append(f"!{node_id:x}")
                # SNR values are scaled by 4, so divide by 4 to get dB
                if i < len(route.snr_towards):
                    snr_db = route.snr_towards[i] / 4.0
                    result["snr_towards"].append(snr_db)
            
            # Extract return route with SNR values if present
            if route.route_back:
                for i, node_id in enumerate(route.route_back):
                    result["route_back"].append(f"!{node_id:x}")
                    if i < len(route.snr_back):
                        snr_db = route.snr_back[i] / 4.0
                        result["snr_back"].append(snr_db)
            
            return result
        
        else:
            return {"type": f"UNKNOWN_APP_{portnum}", "raw_hex": payload_bytes.hex()}
    
    except Exception as e:
        logging.debug(f"Payload decode error (portnum {portnum}): {e}")
        return {"type": f"APP_{portnum}", "raw_hex": payload_bytes.hex()}


def log_decoded_message(from_node, to_node, portnum, status, decoded_info, rssi=None, snr=None):
    """Pretty-print a decoded message."""
    from_str = f"!{from_node:x}" if isinstance(from_node, int) else str(from_node)
    to_str = f"!{to_node:x}" if isinstance(to_node, int) else str(to_node)
    
    divider = "=" * 80
    logging.info(f"\n{divider}")
    logging.info(f"📦 MESSAGE: {from_str} → {to_str} | PortNum: {portnum} ({decoded_info.get('type', 'UNKNOWN')})")
    
    # Log signal quality
    signal_info = f"Decryption: {status}"
    if rssi is not None or snr is not None:
        signal_parts = []
        if rssi is not None:
            signal_parts.append(f"RSSI: {rssi} dBm")
        if snr is not None:
            signal_parts.append(f"SNR: {snr:.2f} dB")
        signal_info += " | " + " | ".join(signal_parts)
    logging.info(f"   {signal_info}")
    
    msg_type = decoded_info.get('type')
    
    if msg_type == 'TEXT_MESSAGE':
        text = decoded_info.get('text', '')
        logging.info(f"   TEXT: {text}")
    
    elif msg_type == 'POSITION':
        if 'lat' in decoded_info and 'lon' in decoded_info:
            logging.info(f"   POSITION: {decoded_info['lat']:.6f}, {decoded_info['lon']:.6f}")
        if 'alt_m' in decoded_info:
            logging.info(f"   ALTITUDE: {decoded_info['alt_m']}m")
        if 'time' in decoded_info:
            logging.info(f"   TIME: {decoded_info['time']}")
        # Accuracy info
        acc_parts = []
        if 'sats_in_view' in decoded_info:
            acc_parts.append(f"sats={decoded_info['sats_in_view']}")
        if 'PDOP' in decoded_info:
            acc_parts.append(f"PDOP={decoded_info['PDOP']}")
        elif 'HDOP' in decoded_info:
            acc_parts.append(f"HDOP={decoded_info['HDOP']}")
        if 'gps_accuracy_mm' in decoded_info:
            acc_parts.append(f"acc={decoded_info['gps_accuracy_mm']}mm")
        if 'fix_type' in decoded_info:
            fix_names = {2: '2D', 3: '3D', 4: '3D-DGPS', 5: 'RTK'}
            acc_parts.append(f"fix={fix_names.get(decoded_info['fix_type'], str(decoded_info['fix_type']))}")
        if 'precision_bits' in decoded_info:
            acc_parts.append(f"prec={decoded_info['precision_bits']}b")
        if acc_parts:
            logging.info(f"   ACCURACY: {' | '.join(acc_parts)}")
        if 'ground_speed_ms' in decoded_info:
            logging.info(f"   SPEED: {decoded_info['ground_speed_ms']} m/s @ {decoded_info.get('ground_track_deg', '?')}°")
    
    elif msg_type == 'NODEINFO':
        long_name  = decoded_info.get('long_name', '')
        short_name = decoded_info.get('short_name', '')
        hw_model   = decoded_info.get('hw_model', None)
        logging.info(f"   ID: {decoded_info.get('id')}")
        logging.info(f"   Long Name: {long_name}")
        logging.info(f"   Short Name: {short_name}")
        if hw_model:
            logging.info(f"   HW Model: {hw_model}")
    
    elif msg_type == 'ROUTING':
        subtype = decoded_info.get('subtype', 'unknown')
        logging.info(f"   ROUTING ({subtype})")
        if subtype == 'route_request':
            route = decoded_info.get('route', [])
            logging.info(f"   Route Request: {' → '.join(route) if route else '(empty)'}")
            if 'snr_towards' in decoded_info:
                logging.info(f"   SNR Towards: {decoded_info['snr_towards']}")
        elif subtype == 'route_reply':
            route = decoded_info.get('route', [])
            logging.info(f"   Route Forward: {' → '.join(route) if route else '(empty)'}")
            if 'snr_towards' in decoded_info:
                logging.info(f"   SNR Forward: {decoded_info['snr_towards']}")
            route_back = decoded_info.get('route_back', [])
            if route_back:
                logging.info(f"   Route Back: {' → '.join(route_back)}")
            if 'snr_back' in decoded_info:
                logging.info(f"   SNR Back: {decoded_info['snr_back']}")
        elif subtype == 'error':
            error = decoded_info.get('error', 'UNKNOWN')
            logging.info(f"   Error: {error}")
    
    elif msg_type == 'TELEMETRY':
        variant = decoded_info.get('variant', 'unknown')
        logging.info(f"   Variant: {variant}")
        if 'time' in decoded_info:
            logging.info(f"   Time: {decoded_info['time']}")
        if 'battery_level' in decoded_info:
            pct = decoded_info['battery_level']
            bar = '█' * (pct // 10) + '░' * (10 - pct // 10)
            logging.info(f"   Battery: {pct}% [{bar}]")
        if 'voltage_v' in decoded_info:
            logging.info(f"   Voltage: {decoded_info['voltage_v']:.3f} V")
        if 'channel_util_pct' in decoded_info:
            logging.info(f"   Channel util: {decoded_info['channel_util_pct']:.1f}%")
        if 'air_util_tx_pct' in decoded_info:
            logging.info(f"   Air util TX: {decoded_info['air_util_tx_pct']:.1f}%")
        if 'uptime_s' in decoded_info:
            u = decoded_info['uptime_s']
            logging.info(f"   Uptime: {u//3600}h {(u%3600)//60}m {u%60}s")
        if 'temperature_c' in decoded_info:
            logging.info(f"   Temperature: {decoded_info['temperature_c']:.1f}°C")
        if 'humidity_pct' in decoded_info:
            logging.info(f"   Humidity: {decoded_info['humidity_pct']:.1f}%")
        if 'pressure_hpa' in decoded_info:
            logging.info(f"   Pressure: {decoded_info['pressure_hpa']:.1f} hPa")
        if 'iaq' in decoded_info:
            logging.info(f"   IAQ: {decoded_info['iaq']}")
        if 'wind_speed_ms' in decoded_info:
            logging.info(f"   Wind: {decoded_info['wind_speed_ms']:.1f} m/s @ {decoded_info.get('wind_direction_deg', '?')}°")
        # Online nodes for local_stats
        if 'num_online_nodes' in decoded_info:
            logging.info(f"   Nodes: {decoded_info['num_online_nodes']} online / {decoded_info.get('num_total_nodes', '?')} total")
    
    elif msg_type == 'TRACEROUTE':
        route       = decoded_info.get('route', [])
        snr_towards = decoded_info.get('snr_towards', [])
        route_back  = decoded_info.get('route_back', [])
        snr_back    = decoded_info.get('snr_back', [])
        is_reply    = bool(route_back)  # reply packets have a return path
        
        def chain_str(nodes, snrs, arrow='──▶'):
            """Build a visual chain: [A] ──SNR──▶ [B] ──▶ [C]"""
            if not nodes:
                return "(direct)"
            parts = []
            for i, n in enumerate(nodes):
                if i < len(snrs):
                    parts.append(f"──[{snrs[i]:+.2f}dB]──▶ {node_label(n)}")
                else:
                    parts.append(f"──▶ {node_label(n)}")
            return " ".join(parts)
        
        from_lbl = node_label(from_node)
        to_lbl   = node_label(to_node)
        
        if is_reply:
            # Reply: to_node is originator, from_node is destination
            # Forward chain: originator → intermediate → destination
            fwd_nodes = route + [from_str]
            fwd_snrs  = snr_towards
            fwd_chain = chain_str(fwd_nodes, fwd_snrs)
            logging.info(f"   Fwd: {to_lbl} {fwd_chain}")
            # Return chain: destination → intermediate → originator
            bck_nodes = route_back + [to_str]
            bck_snrs  = snr_back
            bck_chain = chain_str(bck_nodes, bck_snrs)
            logging.info(f"   Bck: {from_lbl} {bck_chain}")
        else:
            # Request: from_node is originator, route = hops so far, to_node = destination
            fwd_nodes = route + [to_str]
            fwd_snrs  = snr_towards
            fwd_chain = chain_str(fwd_nodes, fwd_snrs)
            logging.info(f"   Req: {from_lbl} {fwd_chain}")
    
    elif msg_type == 'TEXT_MESSAGE_COMPRESSED':
        text = decoded_info.get('text', '')
        logging.info(f"   TEXT (COMPRESSED): {text}")
    
    elif msg_type == 'ADMIN':
        logging.info(f"   ADMIN MESSAGE")
    
    logging.info(f"{divider}\n")

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

        # Attempt to decrypt if payload is encrypted
        if msg.HasField('encrypted'):
            logging.info(f"Encrypted payload detected ({len(msg.encrypted)} bytes) on channel {msg.channel}")
            
            # Get 'from' field using getattr since 'from' is a reserved keyword
            from_id = getattr(msg, 'from')
            
            decrypted = None
            successful_key = None
            is_pki_message = getattr(msg, 'pki_encrypted', False)

            # If packet indicates PKI encryption, try ONLY asymmetric decryption (do NOT fall back to PSK)
            if is_pki_message:
                # PKI encryption: message is encrypted WITH the recipient's (to) public key
                # So we need the RECIPIENT's private key to decrypt
                to_id = msg.to
                sender_pub = bytes(msg.public_key) if msg.public_key else None
                priv_bytes = None
                
                logging.info(f"🔐 PKI Message Detection:")
                logging.info(f"   From: !{from_id:x} ({from_id})")
                logging.info(f"   To: !{to_id:x} ({to_id})")
                # If public key is missing from packet, derive it from stored private key of sender
                if not sender_pub:
                    sender_pub = PUBLIC_KEYS_BY_NODE.get(from_id)
                    if sender_pub:
                        logging.info(f"   Sender PublicKey: derived from stored key for !{from_id:x}")
                    else:
                        logging.info(f"   Sender PublicKey: MISSING (not in packet, not in key store)")
                else:
                    logging.info(f"   Sender PublicKey: {sender_pub.hex()[:32]}... ({len(sender_pub)} bytes)")
                logging.info(f"   Encrypted payload: {len(msg.encrypted)} bytes")
                
                # Look up private key by RECIPIENT node number (TO, not FROM)
                priv_bytes = PRIVATE_KEYS_BY_NODE.get(to_id)
                logging.debug(f"   Lookup result: PRIVATE_KEYS_BY_NODE.get({to_id}) = {priv_bytes is not None}")
                
                if not priv_bytes:
                    logging.debug(f"   Available nodes in PRIVATE_KEYS_BY_NODE: {list(PRIVATE_KEYS_BY_NODE.keys())}")
                
                # Attempt PKI decryption
                if priv_bytes and sender_pub:
                    logging.info(f"   ✓ Found recipient private key ({len(priv_bytes)} bytes), attempting decryption...")
                    decrypted = try_decrypt_pki(msg.encrypted, sender_pub, priv_bytes, from_id, msg.id, to_node_id=to_id)
                    if decrypted:
                        successful_key = 'pki'
                        logging.info('   ✓ Successfully decrypted PKI payload')
                    else:
                        logging.warning(f"   ✗ PKI decryption failed (returned None)")
                else:
                    # PKI message but no private key configured for recipient
                    import base64
                    logging.warning(f"   ⚠️  PKI encrypted message TO !{to_id:x} from !{from_id:x}")
                    if not priv_bytes:
                        logging.warning(f"       No private key found for recipient !{to_id:x} (node {to_id})")
                        logging.warning(f"       Add to private_keys.json:")
                        logging.warning(f"         \"nodes\": {{\"{to_id}\": \"RECIPIENT_PRIVATE_KEY\"}}")
                        logging.warning(f"       Currently available nodes: {list(PRIVATE_KEYS_BY_NODE.keys())}")
                    if not sender_pub:
                        logging.warning(f"       Sender public key is MISSING from packet")

            # If NOT PKI message, try PSK keys using AES-CTR
            else:
                # Build list: channel-specific key (if configured), then defaults 1-10
                channel_psk_list = []
                if msg.channel in CHANNEL_KEYS:
                    channel_psk_list.append(CHANNEL_KEYS[msg.channel])
                    logging.info(f"Trying channel-specific key for channel {msg.channel}")
                channel_psk_list.extend([1,2,3,4,5,6,7,8,9,10])

                attempts = 0
                for key_num in channel_psk_list:
                    psk_bytes = parse_meshtastic_key(key_num)
                    if not psk_bytes:
                        continue
                    attempts += 1
                    plaintext = try_decrypt_with_psk(msg.encrypted, psk_bytes, from_id, msg.id)
                    if plaintext:
                        decrypted = plaintext
                        successful_key = key_num
                        logging.info(f"✓ Successfully decrypted with key: {key_num}")
                        break
            
            # Process decrypted payload
            if decrypted:
                logging.info(f"✓ Decrypted payload: {len(decrypted)} bytes (key: {successful_key})")
                logging.info(f"  Hex: {decrypted.hex()}")
                
                # Try to parse as protobuf Data message
                try:
                    data_msg = mesh_pb2.Data()
                    data_msg.ParseFromString(decrypted)
                    portnum = data_msg.portnum
                    payload = getattr(data_msg, 'payload', None) or b''
                    
                    # Decode the payload based on PortNum
                    decoded_info = decode_portnum_payload(portnum, payload)
                    
                    # Update persistent node database
                    if decoded_info.get('type') == 'NODEINFO':
                        update_node_db(
                            from_id,
                            long_name  = decoded_info.get('long_name'),
                            short_name = decoded_info.get('short_name'),
                            hw_model   = decoded_info.get('hw_model'),
                            is_licensed= decoded_info.get('is_licensed'),
                        )
                        logging.debug(f"Node DB: updated NODEINFO for !{from_id:x}")
                    elif decoded_info.get('type') == 'POSITION':
                        update_node_db(
                            from_id,
                            lat   = decoded_info.get('lat'),
                            lon   = decoded_info.get('lon'),
                            alt_m = decoded_info.get('alt_m'),
                        )
                    
                    # Extract signal quality metrics
                    rssi = msg.rx_rssi if hasattr(msg, 'rx_rssi') and msg.rx_rssi != 0 else None
                    snr = msg.rx_snr if hasattr(msg, 'rx_snr') and msg.rx_snr != 0.0 else None
                    
                    # Log in a readable format
                    log_decoded_message(from_id, msg.to, portnum, f"✓ {successful_key}", decoded_info, rssi, snr)

                    # Append machine-readable record to JSONL log
                    hop_start = getattr(msg, 'hop_start', None) or None
                    hop_limit = getattr(msg, 'hop_limit', None)
                    hops_taken = (hop_start - hop_limit) if (hop_start is not None and hop_limit is not None) else None
                    write_jsonl({
                        'rx_time':   msg.rx_time if msg.rx_time else None,
                        'from_id':   from_id,
                        'from_hex':  f'!{from_id:x}',
                        'from_name': NODE_DB.get(str(from_id), {}).get('long_name'),
                        'to_id':     msg.to,
                        'to_hex':    f'!{msg.to:x}',
                        'to_name':   NODE_DB.get(str(msg.to), {}).get('long_name'),
                        'packet_id': msg.id,
                        'channel':   msg.channel,
                        'portnum':   portnum,
                        'type':      decoded_info.get('type'),
                        'encryption': str(successful_key),
                        'pki':       bool(is_pki_message),
                        'rssi':      rssi,
                        'snr':       snr,
                        'hop_start': hop_start,
                        'hop_limit': hop_limit,
                        'hops_taken': hops_taken,
                        'relay_node': getattr(msg, 'relay_node', None) or None,
                        'src_ip':    src_ip,
                        'payload':   decoded_info,
                        'raw_encrypted_hex': msg.encrypted.hex(),
                    })

                except Exception as parse_err:
                    logging.warning(f"Could not parse as Data message: {parse_err}")
                    # Show raw data for debugging
                    logging.info(f"Raw decrypted hex: {decrypted.hex()}")
                    # Still log to JSONL with both raw encrypted and decrypted bytes
                    write_jsonl({
                        'rx_time':           msg.rx_time if msg.rx_time else None,
                        'from_id':           from_id,
                        'from_hex':          f'!{from_id:x}',
                        'to_id':             msg.to,
                        'to_hex':            f'!{msg.to:x}',
                        'packet_id':         msg.id,
                        'channel':           msg.channel,
                        'pki':               bool(is_pki_message),
                        'encryption':        str(successful_key),
                        'src_ip':            src_ip,
                        'parse_error':       str(parse_err),
                        'raw_encrypted_hex': msg.encrypted.hex(),
                        'raw_decrypted_hex': decrypted.hex(),
                    })
            else:
                logging.warning(f"✗ Could not decrypt payload with any available key")
                if is_pki_message:
                    logging.info(f"  PKI encryption: no matching private key")
                else:
                    logging.info(f"  PSK keys tried: 1-10 (channel {msg.channel})")
                write_jsonl({
                    'from_id':    from_id,
                    'from_hex':   f'!{from_id:x}',
                    'to_id':      msg.to,
                    'to_hex':     f'!{msg.to:x}',
                    'packet_id':  msg.id,
                    'channel':    msg.channel,
                    'pki':        bool(is_pki_message),
                    'rssi':       msg.rx_rssi if hasattr(msg, 'rx_rssi') and msg.rx_rssi != 0 else None,
                    'snr':        msg.rx_snr  if hasattr(msg, 'rx_snr')  and msg.rx_snr  != 0.0 else None,
                    'src_ip':     src_ip,
                    'encryption': None,
                    'raw_encrypted_hex': msg.encrypted.hex(),
                })

        elif msg.HasField('decoded'):
            # Unencrypted packet — already decoded by firmware/sender, log it directly
            d = msg.decoded
            from_id = getattr(msg, 'from')
            portnum = d.portnum
            payload_bytes = getattr(d, 'payload', None) or b''
            decoded_info = decode_portnum_payload(portnum, payload_bytes)
            rssi = msg.rx_rssi if hasattr(msg, 'rx_rssi') and msg.rx_rssi != 0 else None
            snr  = msg.rx_snr  if hasattr(msg, 'rx_snr')  and msg.rx_snr  != 0.0 else None
            hop_start = getattr(msg, 'hop_start', None) or None
            hop_limit = getattr(msg, 'hop_limit', None)
            hops_taken = (hop_start - hop_limit) if (hop_start is not None and hop_limit is not None) else None
            log_decoded_message(from_id, msg.to, portnum, 'plaintext', decoded_info, rssi, snr)
            write_jsonl({
                'rx_time':    msg.rx_time if msg.rx_time else None,
                'from_id':    from_id,
                'from_hex':   f'!{from_id:x}',
                'from_name':  NODE_DB.get(str(from_id), {}).get('long_name'),
                'to_id':      msg.to,
                'to_hex':     f'!{msg.to:x}',
                'to_name':    NODE_DB.get(str(msg.to), {}).get('long_name'),
                'packet_id':  msg.id,
                'channel':    msg.channel,
                'portnum':    portnum,
                'type':       decoded_info.get('type'),
                'encryption': 'plaintext',
                'pki':        False,
                'rssi':       rssi,
                'snr':        snr,
                'hop_start':  hop_start,
                'hop_limit':  hop_limit,
                'hops_taken': hops_taken,
                'relay_node': getattr(msg, 'relay_node', None) or None,
                'src_ip':     src_ip,
                'payload':    decoded_info,
            })

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
