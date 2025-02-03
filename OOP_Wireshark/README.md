# WiresharkLimited

WiresharkLimited is a lightweight, extensible packet sniffer implemented in C using libpcap. It provides functionality similar to Wireshark/TCPDump with support for multiple network protocols and packet filtering capabilities.

## Features

- **Protocol Support**:
  - Network Layer: IP packet analysis
  - Transport Layer: TCP, UDP, ICMP
  - Application Layer: HTTP, HTTPS, SSH
- **Real-time Packet Analysis**: View packet details as they are captured
- **Flexible Filtering**: Filter packets by IP address and/or port number
- **Capture File Support**: Save captures in PCAP format compatible with Wireshark
- **Object-Oriented Design**: Modular and extensible architecture

## Prerequisites

- GCC compiler
- libpcap development library
- Root privileges for packet capture

### Installation on Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install gcc libpcap-dev
```

### Installation on CentOS/RHEL
```bash
sudo yum install gcc libpcap-devel
```

### Installation on macOS
```bash
brew install libpcap
```

## Building

1. Clone the repository:
```bash
https://github.com/AliMamdouh2025/STM_Advanced_Linux_Trainning.git
cd OOP_Wireshark
```

2. Compile the program:
```bash
gcc -o wireSharkLimited wireSharkLimited.c -lpcap
```

## Usage

WiresharkLimited requires root privileges to capture packets. Basic usage:

```bash
sudo ./wireSharkLimited [options]
```

### Command Line Options

- `-i <interface>`: Specify network interface (default: automatically selected)
- `-ip <address>`: Filter packets by IP address
- `-port <number>`: Filter packets by port number
- `-w <filename>`: Save capture to file (PCAP format)

### Examples

1. Basic capture on default interface:
```bash
sudo ./wireSharkLimited
```

2. Capture on specific interface:
```bash
sudo ./wireSharkLimited -i eth0
```

3. Filter by IP address:
```bash
sudo ./wireSharkLimited -ip 192.168.1.100
```

4. Filter by port:
```bash
sudo ./wireSharkLimited -port 80
```

5. Save capture to file:
```bash
sudo ./wireSharkLimited -w capture.pcap
```

6. Combine filters:
```bash
sudo ./wireSharkLimited -i eth0 -ip 192.168.1.100 -port 443 -w capture.pcap
```

## Output Format

The sniffer provides detailed information for each captured packet:

### IP Packets
- Source and destination IP addresses
- Protocol number
- Header length and total length

### TCP Packets
- Source and destination ports
- Sequence and acknowledgment numbers
- TCP flags
- Application layer protocol (if identifiable)

### UDP Packets
- Source and destination ports
- Packet length
- Checksum

### ICMP Packets
- ICMP type
- ICMP code
- Checksum

## Object-Oriented Design

WiresharkLimited implements OOP concepts in C through:

1. **Inheritance**: Base `Packet` structure inherited by specific packet types
2. **Polymorphism**: Function pointers for packet parsing and saving
3. **Encapsulation**: Data and methods grouped in packet structures
4. **Abstraction**: Common interface for different packet types

## Limitations

- Requires root privileges for packet capture
- Limited to IPv4 packets
- Application layer protocol detection based on port numbers
- No packet injection capabilities
- No GUI interface

## Troubleshooting

1. **Permission Denied**
   ```bash
   sudo ./wireSharkLimited
   ```

2. **Interface Not Found**
   - Check available interfaces:
   ```bash
   ip link show  # Linux
   ifconfig      # macOS
   ```

3. **Compilation Errors**
   - Ensure libpcap is installed:
   ```bash
   ldconfig -p | grep libpcap
   ```

## Video
https://drive.google.com/file/d/18h1hGdQI91PoTVDf8TXEigPwJCRwpXV_/view?usp=sharing
