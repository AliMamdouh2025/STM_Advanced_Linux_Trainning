# WireFish C Packet Sniffer

WireFish is a network packet sniffer written in C that leverages the [libpcap](https://www.tcpdump.org/) library to capture live network traffic. This tool analyzes IP packets and digests various protocols at the transport layer (TCP, UDP, and ICMP) as well as performing basic application layer analysis (HTTP). Additionally, it supports filtering by specific IP addresses and ports and can save the captured packets in a pcap file for later analysis with tools like Wireshark.

## Features

- **Live Packet Capture:** Uses libpcap to capture network traffic in real time.
- **Protocol Parsing:**
  - **IP:** Parses IPv4 header fields (source/destination IP, protocol, etc.).
  - **TCP:** Analyzes TCP headers (ports, sequence, acknowledgment numbers) and inspects application data (e.g., HTTP requests).
  - **UDP:** Processes UDP packet headers.
  - **ICMP:** Extracts ICMP header information.
- **Application Layer Analysis:**  
  Basic HTTP protocol detection is performed by inspecting TCP payloads.
- **Filtering:**  
  Filter packets based on a specified IP address or port using command-line options.
- **Capture Saving:**  
  Optionally save the captured packets to a pcap file, enabling further analysis with Wireshark.
- **Graceful Termination:**  
  Implements signal handling to ensure all resources are cleaned up properly when the program exits (e.g., on Ctrl+C).

## Dependencies

- **libpcap:**  
  - **Ubuntu/Debian:** `sudo apt-get install libpcap-dev`
  - **Fedora:** `sudo dnf install libpcap-devel`
- **C Compiler:**  
  Any standard C compiler (e.g., gcc, clang)

## Compilation

To compile the WireFish C Packet Sniffer, run:

```bash
gcc -o wirefish_c wirefish_c.c -lpcap
```

Make sure that the libpcap development package is installed on your system.

## Usage

Run the application with the following command-line options:

```
./wirefish_c [-i interface] [-ip target_ip] [-port target_port] [-w output_file]
```

- `-i interface`  
  Specify the network interface for capturing packets (e.g., `eth0`, `wlan0`).  
  If not provided, the program will attempt to use the first non-loopback interface.
- `-ip target_ip`  
  Filter packets based on the specified IP address.
- `-port target_port`  
  Filter packets based on the specified port.
- `-w output_file`  
  (Optional) Save the captured packets to a pcap file.

### Example

Capture packets on interface `eth0`, filtering for IP address `192.168.1.100` and port `80`, and save the capture to `capture.pcap`:

```bash
./wirefish_c -i eth0 -ip 192.168.1.100 -port 80 -w capture.pcap
```


## Video Demonstration

A short video demonstrating the design and usage of WireFish in C is available here:  
[Video Link](https://drive.google.com/file/d/18h1hGdQI91PoTVDf8TXEigPwJCRwpXV_/view?usp=drive_link)


