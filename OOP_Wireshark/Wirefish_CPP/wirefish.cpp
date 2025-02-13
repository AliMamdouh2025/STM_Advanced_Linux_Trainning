#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>       // struct ip
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <netinet/ip_icmp.h>  // struct icmphdr
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <algorithm>
#include <cctype>

using namespace std;

// Abstract base class for any packet that can be parsed and displayed.
class Packet 
{
public:
    virtual void parse(const u_char* data, size_t length) = 0;
    // For text-based protocols, we overload parse() to accept a string.
    virtual void parse(const string& data) {}
    virtual void display() const = 0;
    virtual ~Packet() {}
};

//--------------------------------------------------
// IPPacket: Responsible for digesting IPv4 header fields.
class IPPacket : public Packet 
{
private:
    uint8_t version;
    uint8_t ihl; // Internet Header Length (in 32-bit words)
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    string srcIP;
    string dstIP;
public:
    void parse(const u_char* data, size_t length) override 
    {
        if (length < 20) return;
        version = data[0] >> 4;
        ihl = data[0] & 0x0F;
        tos = data[1];
        totalLength = ntohs(*(uint16_t*)(data + 2));
        identification = ntohs(*(uint16_t*)(data + 4));
        flagsFragment = ntohs(*(uint16_t*)(data + 6));
        ttl = data[8];
        protocol = data[9];
        checksum = ntohs(*(uint16_t*)(data + 10));
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, data + 12, ipStr, INET_ADDRSTRLEN);
        srcIP = ipStr;
        inet_ntop(AF_INET, data + 16, ipStr, INET_ADDRSTRLEN);
        dstIP = ipStr;
    }
    void display() const override 
    {
        cout << "----- IP Packet -----" << endl;
        cout << "Version: " << static_cast<int>(version)
             << ", Header Length: " << static_cast<int>(ihl * 4) << " bytes" << endl;
        cout << "TOS: " << static_cast<int>(tos)
             << ", Total Length: " << totalLength << endl;
        cout << "Identification: " << identification
             << ", Flags+Fragment: " << flagsFragment << endl;
        cout << "TTL: " << static_cast<int>(ttl)
             << ", Protocol: " << static_cast<int>(protocol) << endl;
        cout << "Checksum: " << checksum << endl;
        cout << "Source IP: " << srcIP
             << ", Destination IP: " << dstIP << endl;
    }
    uint8_t getProtocol() const { return protocol; }
    uint8_t getIHL() const { return ihl; }
};

//--------------------------------------------------
// TCPPacket: Parses and displays a TCP header.
class TCPPacket : public Packet 
{
private:
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq;
    uint32_t ack;
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPtr;
public:
    void parse(const u_char* data, size_t length) override 
    {
        if (length < 20) return;
        srcPort = ntohs(*(uint16_t*)(data));
        dstPort = ntohs(*(uint16_t*)(data + 2));
        seq = ntohl(*(uint32_t*)(data + 4));
        ack = ntohl(*(uint32_t*)(data + 8));
        dataOffset = (data[12] >> 4) * 4;
        flags = data[13];
        window = ntohs(*(uint16_t*)(data + 14));
        checksum = ntohs(*(uint16_t*)(data + 16));
        urgentPtr = ntohs(*(uint16_t*)(data + 18));
    }
    void display() const override 
    {
        cout << "----- TCP Packet -----" << endl;
        cout << "Src Port: " << srcPort << ", Dst Port: " << dstPort << endl;
        cout << "Seq: " << seq << ", Ack: " << ack << endl;
        cout << "Header Length: " << static_cast<int>(dataOffset) << " bytes" << endl;
        cout << "Flags: " << static_cast<int>(flags)
             << ", Window: " << window << endl;
        cout << "Checksum: " << checksum
             << ", Urgent Ptr: " << urgentPtr << endl;
    }
};

//--------------------------------------------------
// UDPPacket: Parses and displays a UDP header.
class UDPPacket : public Packet 
{
private:
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t lengthField;
    uint16_t checksum;
public:
    void parse(const u_char* data, size_t length) override 
    {
        if (length < 8) return;
        srcPort = ntohs(*(uint16_t*)(data));
        dstPort = ntohs(*(uint16_t*)(data + 2));
        lengthField = ntohs(*(uint16_t*)(data + 4));
        checksum = ntohs(*(uint16_t*)(data + 6));
    }
    void display() const override 
    {
        cout << "----- UDP Packet -----" << endl;
        cout << "Src Port: " << srcPort << ", Dst Port: " << dstPort << endl;
        cout << "Length: " << lengthField
             << ", Checksum: " << checksum << endl;
    }
};

//--------------------------------------------------
// ICMPPacket: Parses and displays an ICMP header.
class ICMPPacket : public Packet 
{
private:
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
public:
    void parse(const u_char* data, size_t length) override 
    {
        if (length < 4) return;
        type = data[0];
        code = data[1];
        checksum = ntohs(*(uint16_t*)(data + 2));
    }
    void display() const override 
    {
        cout << "----- ICMP Packet -----" << endl;
        cout << "Type: " << static_cast<int>(type)
             << ", Code: " << static_cast<int>(code) << endl;
        cout << "Checksum: " << checksum << endl;
    }
};

//--------------------------------------------------
// Application layer abstract class for text-based protocols.
class ApplicationProtocol 
{
public:
    virtual void parse(const string& data) = 0;
    virtual void display() const = 0;
    virtual ~ApplicationProtocol() {}
};

// Intermediate class for text-based protocols (HTTP, FTP)
class TextBasedProtocol : public ApplicationProtocol 
{
protected:
    vector<string> lines;
    void splitLines(const string& data) 
    {
        lines.clear();
        istringstream iss(data);
        string line;
        while (getline(iss, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            lines.push_back(line);
        }
    }
public:
    virtual ~TextBasedProtocol() {}
};

//--------------------------------------------------
// HTTPProtocol: Inherits from TextBasedProtocol and Packet.
class HTTPProtocol : public TextBasedProtocol, public Packet 
{
private:
    string method;
    string uri;
    string version;
public:
    void parse(const string& data) override 
    {
        splitLines(data);
        if (!lines.empty()) 
        {
            istringstream iss(lines[0]);
            iss >> method >> uri >> version;
        }
    }
    // Overload the binary parse (not used in this context) BUT must be override to avoid Ambigous inheritence bug 
    void parse(const u_char* data, size_t length) override {}
    void display() const override 
    {
        cout << "----- HTTP Protocol -----" << endl;
        cout << "Method: " << method << ", URI: " << uri 
             << ", Version: " << version << endl;
        cout << "Headers:" << endl;
        for (size_t i = 1; i < lines.size(); ++i)
            cout << lines[i] << endl;
    }
};

//--------------------------------------------------
// FTPProtocol: Inherits from TextBasedProtocol and Packet.
class FTPProtocol : public TextBasedProtocol, public Packet {
private:
    string command;
    string argument;
public:
    void parse(const string& data) override {
        splitLines(data);
        if (!lines.empty()) {
            istringstream iss(lines[0]);
            iss >> command;
            getline(iss, argument);
            if (!argument.empty() && argument[0] == ' ')
                argument.erase(0, 1);
        }
    }
    // Overload the binary parse (not used in this context)
    void parse(const u_char* data, size_t length) override {}
    void display() const override {
        cout << "----- FTP Protocol -----" << endl;
        cout << "Command: " << command 
             << ", Argument: " << argument << endl;
    }
};

//--------------------------------------------------
// DNSProtocol: Inherits from ApplicationProtocol and Packet.
// Real DNS parser implementation.
class DNSProtocol : public ApplicationProtocol, public Packet {
private:
    uint16_t transactionID;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
    vector<string> questions;  // We'll store a summary string for each question

    // Helper function to parse a domain name from the DNS packet.
    // It supports pointer compression in a basic way.
    string parseDomainName(const u_char* data, size_t length, size_t &offset) 
    {
        string domain;
        bool jumped = false;
        size_t originalOffset = offset; // Save offset if we jump via pointer.
        int loops = 0;  // Prevent infinite loops.
        
        while (offset < length && loops < 50) 
        {
            uint8_t labelLen = data[offset];
            if (labelLen == 0) 
            {
                offset++; // Skip the null terminator.
                break;
            }
            // Check if this label is a pointer (two high bits set)
            if ((labelLen & 0xC0) == 0xC0) 
            {
                if (offset + 1 >= length) 
                {
                    throw runtime_error("DNS pointer out of bounds");
                }
                uint16_t pointer = ((labelLen & 0x3F) << 8) | data[offset + 1];
                if (!jumped) 
                {
                    originalOffset = offset + 2;
                }
                offset = pointer;
                jumped = true;
                continue;
            } else 
            {
                offset++; // Move past the length byte.
                if (offset + labelLen > length) {
                    throw runtime_error("DNS label exceeds packet length");
                }
                if (!domain.empty()) {
                    domain.push_back('.');
                }
                domain.append(reinterpret_cast<const char*>(data + offset), labelLen);
                offset += labelLen;
            }
            loops++;
        }
        // If we jumped, restore the original offset to continue parsing subsequent sections.
        if (jumped) {
            offset = originalOffset;
        }
        return domain;
    }

public:
    // Parse binary DNS data.
    void parse(const u_char* data, size_t length) override {
        if (length < 12) {
            throw runtime_error("DNS packet too short");
        }
        transactionID = ntohs(*(reinterpret_cast<const uint16_t*>(data)));
        flags = ntohs(*(reinterpret_cast<const uint16_t*>(data + 2)));
        qdCount = ntohs(*(reinterpret_cast<const uint16_t*>(data + 4)));
        anCount = ntohs(*(reinterpret_cast<const uint16_t*>(data + 6)));
        nsCount = ntohs(*(reinterpret_cast<const uint16_t*>(data + 8)));
        arCount = ntohs(*(reinterpret_cast<const uint16_t*>(data + 10)));
        
        // Parse question section (if any)
        size_t offset = 12;
        questions.clear();
        for (int i = 0; i < qdCount; i++) {
            // Parse the domain name from the question.
            string domain = parseDomainName(data, length, offset);
            // Ensure there's enough data for QTYPE and QCLASS (4 bytes).
            if (offset + 4 > length) {
                throw runtime_error("DNS question section truncated");
            }
            uint16_t qtype = ntohs(*(reinterpret_cast<const uint16_t*>(data + offset)));
            uint16_t qclass = ntohs(*(reinterpret_cast<const uint16_t*>(data + offset + 2)));
            offset += 4;
            // Save a summary of the question.
            ostringstream oss;
            oss << domain << " (Type " << qtype << ", Class " << qclass << ")";
            questions.push_back(oss.str());
        }
    }
    
    // Not used for binary DNS parsing.
    void parse(const string& data) override {}
    
    void display() const override 
    {
        cout << "----- DNS Protocol -----" << endl;
        cout << "Transaction ID: " << transactionID 
             << ", Flags: " << flags << endl;
        cout << "Questions: " << qdCount 
             << ", Answers: " << anCount 
             << ", Authority: " << nsCount 
             << ", Additional: " << arCount << endl;
        for (size_t i = 0; i < questions.size(); i++) {
            cout << "Question " << i+1 << ": " << questions[i] << endl;
        }
    }
};
//--------------------------------------------------
// WireFish: Main sniffer class that uses libpcap to capture packets,
// applies filtering, and dispatches them to the appropriate parser.
class WireFish {
private:
    pcap_t* handle;
    pcap_dumper_t* dumper;
    string filterIP;
    int filterPort;
    int linkLayerOffset;
public:
    WireFish() : handle(nullptr), dumper(nullptr), filterPort(0), linkLayerOffset(14) {}
    ~WireFish() 
    {
        if (handle) pcap_close(handle);
    }
    // Initializes the sniffer on the given device with optional filtering.
    bool init(const char* device, const string& filterIP, int filterPort, const string& outFile="") 
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
        if (!handle) 
        {
            cerr << "Error opening device: " << errbuf << endl;
            return false;
        }
        int dlt = pcap_datalink(handle);
        if (dlt == DLT_EN10MB) 
        {            // Ethernet
            linkLayerOffset = 14;
        } else if (dlt == DLT_IEEE802_11 || dlt == DLT_IEEE802_11_RADIO) 
        {
            linkLayerOffset = 32;
        } else 
        {
            linkLayerOffset = 14;
        }
        this->filterIP = filterIP;
        this->filterPort = filterPort;
        if (!outFile.empty()) 
        {
            dumper = pcap_dump_open(handle, outFile.c_str());
            if (!dumper) 
            {
                cerr << "Error opening dump file: " << pcap_geterr(handle) << endl;
            }
        }
        return true;
    }

    void start() 
    {
        pcap_loop(handle, 0, packetCallback, reinterpret_cast<u_char*>(this));
    }

    // Static callback wrapper.
    static void packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
    {
        WireFish* wf = reinterpret_cast<WireFish*>(user);
        wf->processPacket(header, packet);
    }

    // Refactored processPacket function using polymorphism.
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
        // Save packet to file if dumper is open.
        if (dumper) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet);
        }
        // Ensure packet is large enough for an IP header.
        if (header->caplen < static_cast<size_t>(linkLayerOffset + sizeof(struct ip)))
            return;
        const u_char* ipData = packet + linkLayerOffset;
        // Process IP packet polymorphically.
        unique_ptr<Packet> ipPkt = make_unique<IPPacket>();
        ipPkt->parse(ipData, header->caplen - linkLayerOffset);
        // Apply IP filtering if set.
        if (!filterIP.empty()) {
            char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ipData + 12, srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, ipData + 16, dstIP, INET_ADDRSTRLEN);
            if (filterIP != srcIP && filterIP != dstIP)
                return;
        }
        ipPkt->display();
        // Determine transport protocol.
        uint8_t proto = ipData[9];
        int ipHeaderLen = (ipData[0] & 0x0F) * 4;
        unique_ptr<Packet> transPkt;
        if (proto == IPPROTO_TCP && 
            header->caplen >= static_cast<size_t>(linkLayerOffset + ipHeaderLen + sizeof(struct tcphdr))) {
            const u_char* tcpData = ipData + ipHeaderLen;
            transPkt = make_unique<TCPPacket>();
            transPkt->parse(tcpData, header->caplen - linkLayerOffset - ipHeaderLen);
            struct tcphdr* tcpHdr = reinterpret_cast<struct tcphdr*>(const_cast<u_char*>(tcpData));
            int srcPort = ntohs(tcpHdr->th_sport);
            int dstPort = ntohs(tcpHdr->th_dport);
            if (filterPort != 0 && filterPort != srcPort && filterPort != dstPort)
                return;
            transPkt->display();
            // Process application-layer HTTP if port 80 is involved.
            if (srcPort == 80 || dstPort == 80) {
                int tcpHeaderLen = (tcpData[12] >> 4) * 4;
                string appData(reinterpret_cast<const char*>(tcpData + tcpHeaderLen),
                               header->caplen - linkLayerOffset - ipHeaderLen - tcpHeaderLen);
                unique_ptr<Packet> httpPkt = make_unique<HTTPProtocol>();
                httpPkt->parse(appData);
                httpPkt->display();
            }
        }
        else if (proto == IPPROTO_UDP && 
                 header->caplen >= static_cast<size_t>(linkLayerOffset + ipHeaderLen + sizeof(struct udphdr))) {
            const u_char* udpData = ipData + ipHeaderLen;
            transPkt = make_unique<UDPPacket>();
            transPkt->parse(udpData, header->caplen - linkLayerOffset - ipHeaderLen);
            struct udphdr* udpHdr = reinterpret_cast<struct udphdr*>(const_cast<u_char*>(udpData));
            int srcPort = ntohs(udpHdr->uh_sport);
            int dstPort = ntohs(udpHdr->uh_dport);
            if (filterPort != 0 && filterPort != srcPort && filterPort != dstPort)
                return;
            transPkt->display();
            // Process DNS if port 53 is involved.
            if (srcPort == 53 || dstPort == 53) {
                string appData(reinterpret_cast<const char*>(udpData + sizeof(struct udphdr)),
                               header->caplen - linkLayerOffset - ipHeaderLen - sizeof(struct udphdr));
                unique_ptr<Packet> dnsPkt = make_unique<DNSProtocol>();
                dnsPkt->parse(appData);
                dnsPkt->display();
            }
        }
        else if (proto == IPPROTO_ICMP) {
            const u_char* icmpData = ipData + ipHeaderLen;
            transPkt = make_unique<ICMPPacket>();
            transPkt->parse(icmpData, header->caplen - linkLayerOffset - ipHeaderLen);
            transPkt->display();
        }
        else {
            cout << "Other Protocol Packet" << endl;
        }
        cout << "-------------------------------------" << endl;
    }
};

//
// main(): Parse command-line options and start the sniffer.
// Usage: wirefish <interface> [filter_ip] [filter_port] [output_file (optional)]
//
int main(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        cerr << "Usage: " << argv[0] << " <interface> [filter_ip] [filter_port] [output_file]" << endl;
        return 1;
    }
    const char* interface = argv[1];
    string filterIP = (argc >= 3) ? argv[2] : "";
    int filterPort = (argc >= 4) ? atoi(argv[3]) : 0;
    string outFile = (argc >= 5) ? argv[4] : "";

    WireFish sniffer;
    if (!sniffer.init(interface, filterIP, filterPort, outFile)) 
    {
        return 1;
    }
    sniffer.start();
    return 0;
}
