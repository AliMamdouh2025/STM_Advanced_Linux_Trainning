# WireFish Packet Sniffer

**WireFish** is a C++ packet sniffer built using object-oriented programming (OOP) principles. It captures network packets in real-time, parses them through a hierarchy of protocol-specific classes, and displays detailed information for each packet. WireFish supports IP, TCP, UDP, ICMP, and several application layer protocols (HTTP, DNS, FTP) and offers optional filtering and capture saving functionality.

## Features

- **IP Packet Parsing:** Extracts and displays key fields from IPv4 headers.
- **Transport Layer Analysis:**
  - **TCP:** Parses source/destination ports, sequence and acknowledgment numbers, flags, etc.
  - **UDP:** Processes UDP header details.
  - **ICMP:** Analyzes ICMP packet fields.
- **Application Layer Parsing:**
  - **HTTP:** Extracts HTTP request/response information.
  - **DNS:** Parses DNS transaction details including questions and responses.
  - **FTP:** Processes FTP commands with arguments.
- **Filtering:** Filter packets by specific IP addresses or ports via command-line options.
- **Capture Saving:** Optionally save captured packets to a file in pcap format, making them viewable in tools like Wireshark.
- **Robust OOP Design:** Utilizes abstraction, inheritance, and polymorphism to achieve modular and extensible code.

## Dependencies

- **libpcap:** Packet capturing library.  
  - **Ubuntu/Debian:** `sudo apt-get install libpcap-dev`
  - **Fedora:** `sudo dnf install libpcap-devel`
- **C++ Compiler:** g++ (supporting C++11 or later)

## Installation



 **Compile the Code:**

   ```bash
   g++ -std=c++11 -o wirefish wirefish.cpp -lpcap
   ```

   *Ensure that the `libpcap` development libraries are installed on your system.*

## Usage

Run the application with the following command-line arguments:

```
wirefish <interface> [filter_ip] [filter_port] [output_file]
```

- `<interface>`: The network interface to capture packets (e.g., `eth0`, `wlan0`).
- `[filter_ip]`: *(Optional)* Only capture packets with the specified IP address.
- `[filter_port]`: *(Optional)* Only capture packets with the specified port.
- `[output_file]`: *(Optional)* Save the captured packets to a file (in pcap format).

### Example

Capture packets on `eth0`, filtering for IP `192.168.1.1` and port `80`, and save the capture to `capture.pcap`:

```bash
./wirefish eth0 192.168.1.1 80 capture.pcap
```

## Code Structure

- **Packet (Abstract Base Class):**  
  Defines the interface for all packet types with pure virtual functions `parse()` and `display()`.

- **IPPacket, TCPPacket, UDPPacket, ICMPPacket:**  
  Derived classes that parse and display respective protocol header information.

- **Application Layer Protocols:**  
  - **HTTPProtocol, FTPProtocol, DNSProtocol:**  
    Extend a text-based protocol class to handle specific application-layer data.
  
- **WireFish Class:**  
  Manages the packet capture using `libpcap`, applies filtering based on user input, and delegates processing to the appropriate protocol parser via polymorphism.

- **Main Function:**  
  Parses command-line options, initializes the sniffer, and starts the packet capture loop.


## Video Demonstration

A short video illustrating how OOP concepts were applied in the design and implementation of WireFish is available here:  
[Video Link](https://drive.google.com/file/d/19PuaLlelT7dzRSxXigyL5FuwQWerZL-_/view?usp=sharing)


