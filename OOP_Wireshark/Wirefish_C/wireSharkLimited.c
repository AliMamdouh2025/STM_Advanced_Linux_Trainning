#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#define SNAP_LEN 65535
#define SIZE_ETHERNET 14
#define MAX_PACKET_SIZE 65535
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define SSH_PORT 22

// Forward declarations
typedef struct Packet Packet;
typedef struct PacketCapture PacketCapture;

// Base packet structure
typedef struct Packet 
{
    void (*parse)(struct Packet*, const u_char*, struct pcap_pkthdr*);
    void (*save)(struct Packet*, FILE*);
    const u_char* raw_data;
    struct pcap_pkthdr* header;
} Packet;

// IP packet structure
typedef struct IPPacket {
    Packet base;
    struct ip* ip_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
} IPPacket;

// TCP packet structure
typedef struct TCPPacket {
    Packet base;
    struct ip* ip_header;
    struct tcphdr* tcp_header;
    char* payload;
    int payload_length;
} TCPPacket;

// UDP packet structure
typedef struct UDPPacket {
    Packet base;
    struct ip* ip_header;
    struct udphdr* udp_header;
    char* payload;
    int payload_length;
} UDPPacket;

// ICMP packet structure
typedef struct ICMPPacket {
    Packet base;
    struct ip* ip_header;
    struct icmp* icmp_header;
} ICMPPacket;

// Packet capture manager
typedef struct PacketCapture {
    pcap_t* handle;
    char filter_exp[256];
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE* output_file;
    char* target_ip;
    int target_port;
    int packet_count;
    int save_to_file;
} PacketCapture;

// Global capture manager for signal handling
PacketCapture* global_capture = NULL;

// Function prototypes
void cleanup_and_exit(int signal);
void parse_ip_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header);
void parse_tcp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header);
void parse_udp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header);
void parse_icmp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header);
void save_packet(Packet* self, FILE* file);
void analyze_application_layer(TCPPacket* tcp_pkt);
int is_printable(const char* payload, int len);

// Signal handler for graceful cleanup
void cleanup_and_exit(int signal) 
{
    if (global_capture) 
    {
        if (global_capture->output_file) 
        {
            fclose(global_capture->output_file);
        }
        if (global_capture->handle) 
        {
            pcap_close(global_capture->handle);
        }
        free(global_capture);
    }
    printf("\nCapture completed. Exiting...\n");
    exit(0);
}

// Packet creation functions
IPPacket* create_ip_packet() 
{
    IPPacket* pkt = (IPPacket*)calloc(1, sizeof(IPPacket));
    if (!pkt) return NULL;
    pkt->base.parse = parse_ip_packet;
    pkt->base.save = save_packet;
    return pkt;
}

TCPPacket* create_tcp_packet() 
{
    TCPPacket* pkt = (TCPPacket*)calloc(1, sizeof(TCPPacket));
    if (!pkt) return NULL;
    pkt->base.parse = parse_tcp_packet;
    pkt->base.save = save_packet;
    return pkt;
}

UDPPacket* create_udp_packet() 
{
    UDPPacket* pkt = (UDPPacket*)calloc(1, sizeof(UDPPacket));
    if (!pkt) return NULL;
    pkt->base.parse = parse_udp_packet;
    pkt->base.save = save_packet;
    return pkt;
}

ICMPPacket* create_icmp_packet() 
{
    ICMPPacket* pkt = (ICMPPacket*)calloc(1, sizeof(ICMPPacket));
    if (!pkt) return NULL;
    pkt->base.parse = parse_icmp_packet;
    pkt->base.save = save_packet;
    return pkt;
}

// Packet parsing implementations
void parse_ip_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header) 
{
    IPPacket* ip_pkt = (IPPacket*)self;
    ip_pkt->ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    
    inet_ntop(AF_INET, &(ip_pkt->ip_header->ip_src), ip_pkt->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_pkt->ip_header->ip_dst), ip_pkt->dst_ip, INET_ADDRSTRLEN);
    
    printf("\nIP Packet:\n");
    printf("Source IP: %s\n", ip_pkt->src_ip);
    printf("Destination IP: %s\n", ip_pkt->dst_ip);
    printf("Protocol: %d\n", ip_pkt->ip_header->ip_p);
}

void analyze_application_layer(TCPPacket* tcp_pkt) 
{
    uint16_t src_port = ntohs(tcp_pkt->tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_pkt->tcp_header->th_dport);
    
    if (src_port == HTTP_PORT || dst_port == HTTP_PORT) 
    {
        printf("Protocol: HTTP\n");
        if (tcp_pkt->payload && tcp_pkt->payload_length > 0) 
        {
            printf("HTTP Data:\n");
            if (strstr(tcp_pkt->payload, "GET") || strstr(tcp_pkt->payload, "POST")) 
            {
                printf("%.*s\n", tcp_pkt->payload_length, tcp_pkt->payload);
            }
        }
    } else if (src_port == HTTPS_PORT || dst_port == HTTPS_PORT) 
    {
        printf("Protocol: HTTPS (Encrypted)\n");
    } else if (src_port == SSH_PORT || dst_port == SSH_PORT) 
    {
        printf("Protocol: SSH (Encrypted)\n");
    }
}

void parse_tcp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header) 
{
    TCPPacket* tcp_pkt = (TCPPacket*)self;
    
    tcp_pkt->ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = tcp_pkt->ip_header->ip_hl * 4;
    tcp_pkt->tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    int size_tcp = tcp_pkt->tcp_header->th_off * 4;
    
    // Extract payload
    tcp_pkt->payload = (char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    tcp_pkt->payload_length = ntohs(tcp_pkt->ip_header->ip_len) - (size_ip + size_tcp);
    
    printf("\nTCP Packet:\n");
    printf("Source Port: %d\n", ntohs(tcp_pkt->tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_pkt->tcp_header->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp_pkt->tcp_header->th_seq));
    printf("ACK Number: %u\n", ntohl(tcp_pkt->tcp_header->th_ack));
    
    analyze_application_layer(tcp_pkt);
}

void parse_udp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header) 
{
    UDPPacket* udp_pkt = (UDPPacket*)self;
    
    udp_pkt->ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = udp_pkt->ip_header->ip_hl * 4;
    udp_pkt->udp_header = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
    
    printf("\nUDP Packet:\n");
    printf("Source Port: %d\n", ntohs(udp_pkt->udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_pkt->udp_header->uh_dport));
    printf("Length: %d\n", ntohs(udp_pkt->udp_header->uh_ulen));
}

void parse_icmp_packet(Packet* self, const u_char* packet, struct pcap_pkthdr* header) 
{
    ICMPPacket* icmp_pkt = (ICMPPacket*)self;
    
    icmp_pkt->ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = icmp_pkt->ip_header->ip_hl * 4;
    icmp_pkt->icmp_header = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
    
    printf("\nICMP Packet:\n");
    printf("Type: %d\n", icmp_pkt->icmp_header->icmp_type);
    printf("Code: %d\n", icmp_pkt->icmp_header->icmp_code);
}

// Packet saving implementation
void save_packet(Packet* self, FILE* file) 
{
    if (!file || !self->raw_data || !self->header) return;
    
    // Write packet header
    fwrite(self->header, sizeof(struct pcap_pkthdr), 1, file);
    // Write packet data
    fwrite(self->raw_data, self->header->caplen, 1, file);
}


// Packet callback function
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
{
    PacketCapture* capture = (PacketCapture*)user;
    struct ip* ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    
    // Filter by IP if specified
    if (capture->target_ip) 
    {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        if (strcmp(src_ip, capture->target_ip) != 0) 
        {
            return;
        }
    }
    
    // Create and parse appropriate packet type
    switch (ip_header->ip_p) 
    {
        case IPPROTO_TCP: 
        {
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + (ip_header->ip_hl * 4));
            // Filter by port if specified
            if (capture->target_port != 0 && 
                ntohs(tcp_header->th_sport) != capture->target_port && 
                ntohs(tcp_header->th_dport) != capture->target_port) 
            {
                return;
            }
            
            TCPPacket* tcp_pkt = create_tcp_packet();
            if (!tcp_pkt) 
            {
                fprintf(stderr, "Failed to create TCP packet\n");
                return;
            }
            tcp_pkt->base.raw_data = packet;
            tcp_pkt->base.header = (struct pcap_pkthdr*)header;
            tcp_pkt->base.parse(&tcp_pkt->base, packet, (struct pcap_pkthdr*)header);
            
            if (capture->save_to_file) 
            {
                tcp_pkt->base.save(&tcp_pkt->base, capture->output_file);
            }
            
            free(tcp_pkt);
            break;
        }
        case IPPROTO_UDP: 
        {
            struct udphdr* udp_header = (struct udphdr*)(packet + SIZE_ETHERNET + (ip_header->ip_hl * 4));
            if (capture->target_port != 0 && 
                ntohs(udp_header->uh_sport) != capture->target_port && 
                ntohs(udp_header->uh_dport) != capture->target_port) 
            {
                return;
            }
            
            UDPPacket* udp_pkt = create_udp_packet();
            if (!udp_pkt) 
            {
                fprintf(stderr, "Failed to create UDP packet\n");
                return;
            }
            udp_pkt->base.raw_data = packet;
            udp_pkt->base.header = (struct pcap_pkthdr*)header;
            udp_pkt->base.parse(&udp_pkt->base, packet, (struct pcap_pkthdr*)header);
            
            if (capture->save_to_file) 
            {
                udp_pkt->base.save(&udp_pkt->base, capture->output_file);
            }
            
            free(udp_pkt);
            break;
        }
        case IPPROTO_ICMP: 
        {
            ICMPPacket* icmp_pkt = create_icmp_packet();
            if (!icmp_pkt) 
            {
                fprintf(stderr, "Failed to create ICMP packet\n");
                return;
            }
            icmp_pkt->base.raw_data = packet;
            icmp_pkt->base.header = (struct pcap_pkthdr*)header;
            icmp_pkt->base.parse(&icmp_pkt->base, packet, (struct pcap_pkthdr*)header);
            
            if (capture->save_to_file) 
            {
                icmp_pkt->base.save(&icmp_pkt->base, capture->output_file);
            }
            
            free(icmp_pkt);
            break;
        }
        default: 
        {
            IPPacket* ip_pkt = create_ip_packet();
            if (!ip_pkt) 
            {
                fprintf(stderr, "Failed to create IP packet\n");
                return;
            }
            ip_pkt->base.raw_data = packet;
            ip_pkt->base.header = (struct pcap_pkthdr*)header;
            ip_pkt->base.parse(&ip_pkt->base, packet, (struct pcap_pkthdr*)header);
            
            if (capture->save_to_file) 
            {
                ip_pkt->base.save(&ip_pkt->base, capture->output_file);
            }
            
            free(ip_pkt);
            break;
        }
    }
    
    capture->packet_count++;
}

// Initialize packet capture
PacketCapture* init_capture(const char* interface, const char* target_ip, int target_port, const char* output_file) 
{
    PacketCapture* capture = (PacketCapture*)calloc(1, sizeof(PacketCapture));
    if (!capture) 
    {
        fprintf(stderr, "Failed to allocate capture structure\n");
        return NULL;
    }
    
    // Set filter options
    capture->target_ip = target_ip ? strdup(target_ip) : NULL;
    capture->target_port = target_port;
    capture->save_to_file = output_file != NULL;
    
    // Open capture device
if (interface == NULL) 
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get all network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        free(capture);
        return NULL;
    }

    // Use the first non-loopback interface
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) 
    {
        if (!(d->flags & PCAP_IF_LOOPBACK)) 
        {
            interface = strdup(d->name); // Copy the interface name
            break;
        }
    }

    if (interface == NULL) 
    {
        fprintf(stderr, "No non-loopback device found\n");
        pcap_freealldevs(alldevs);
        free(capture);
        return NULL;
    }

    pcap_freealldevs(alldevs); // Free the device list
}



    // Open the device for capturing
    capture->handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, capture->errbuf);
    if (capture->handle == NULL) 
    {
        fprintf(stderr, "Could not open device %s: %s\n", interface, capture->errbuf);
        free(capture);
        return NULL;
    }
    
    // Open output file if specified
    if (output_file) 
    {
        capture->output_file = fopen(output_file, "wb");
        if (!capture->output_file) 
        {
            fprintf(stderr, "Could not open output file: %s\n", output_file);
            pcap_close(capture->handle);
            free(capture);
            return NULL;
        }
        
        // Write pcap file header
        struct pcap_file_header file_header = 
        {
            .magic = 0xa1b2c3d4,
            .version_major = PCAP_VERSION_MAJOR,
            .version_minor = PCAP_VERSION_MINOR,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = SNAP_LEN,
            .linktype = DLT_EN10MB
        };
        fwrite(&file_header, sizeof(file_header), 1, capture->output_file);
    }
    
    return capture;
}

int main(int argc, char* argv[]) 
{
    char* interface = NULL;
    char* target_ip = NULL;
    int target_port = 0;
    char* output_file = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) 
    {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) 
        {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc) 
        {
            target_ip = argv[++i];
        } else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) 
        {
            target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) 
        {
            output_file = argv[++i];
        }
    }
    
    // Initialize capture
    PacketCapture* capture = init_capture(interface, target_ip, target_port, output_file);
    if (!capture) 
    {
        return 1;
    }
    
    // Set global capture for signal handling
    global_capture = capture;
    signal(SIGINT, cleanup_and_exit);
    
    // Start packet capture
    printf("Starting packet capture...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    pcap_loop(capture->handle, 0, packet_handler, (u_char*)capture);
    
    // Cleanup
    cleanup_and_exit(0);
    return 0;
}