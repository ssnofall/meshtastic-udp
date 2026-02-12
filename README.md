# Meshtastic UDP Logger

This tool monitors Meshtastic UDP packets, decodes them, and saves the decoded data in JSON format. It also logs the raw UDP packets in PCAP files for deeper network analysis. Each packet is automatically organized by the source IP address, and the tool maintains detailed session logs for all captured activity. It’s a simple, efficient way to capture, decode, and store Meshtastic UDP traffic.

<img src="/img/img1.jpg" alt="Mestastic Image" width="500px">


## Features

- Listens for UDP multicast packets from Meshtastic nodes
- Saves raw packets as PCAP files (for Wireshark analysis)
- Saves decoded messages as JSON files
- Organizes data by device IP address
- Real-time packet display in terminal

## Requirements

- Python 3.7+
- Meshtastic node with **firmware 2.6+**
- Meshtastic node **connected to WiFi** with **UDP enabled**
- `mesh_pb2.py` file (Meshtastic protobuf definitions)

### Dependencies
```bash
pip install protobuf
```

## Meshtastic Device Setup

Configure your Meshtastic device:

1. **Firmware**: Version 2.6 or later
2. **WiFi**: Connected to your local network
3. **UDP**: Enabled in network settings

Configure via Meshtastic app or web interface:
- Network → WiFi → Enable and connect to your network
- Network → UDP → Enable UDP

## Configuration

Edit the configuration variables in `main.py`:

```python
MCAST_GRP = '224.0.0.69'        # Meshtastic multicast group
MCAST_PORT = 4403               # Meshtastic UDP port
IFACE_IP = '0.0.0.0'      # Your computer's IP address
```

⚠️ **Important**: Update `IFACE_IP` with your computer's actual IP address.

## Usage

Run the logger:
```bash
python main.py
```

Stop with `Ctrl+C`.

## Getting mesh_pb2.py

Download from the [Meshtastic protobufs repository](https://github.com/meshtastic/protobufs) or generate from their `.proto` files.

## Troubleshooting

**No packets received?**
- Verify `IFACE_IP` matches your computer's IP address
- Confirm Meshtastic device has WiFi and UDP enabled
- Use Wireshark to monitor UDP traffic to verify device broadcasting

**Import errors?**
- Ensure `mesh_pb2.py` is in the same directory as `main.py`
- Check protobuf installation: `pip install protobuf`

## Use Cases

- Monitor mesh network traffic patterns
- Debug Meshtastic device communication
- Analyze message routing and delivery

## Security Notice

Only use on networks you own or have permission to monitor. Captured data may contain private messages and location information.

## License

GNU General Public License v3.0

## Authors
- [snofall](https://github.com/ssnofall)
- [mml](https://github.com/mml)

## Credits

- [Meshtastic Project](https://meshtastic.org/) - Open-source mesh networking platform
- [Protocol Buffers](https://protobuf.dev/) - Google's data serialization framework
