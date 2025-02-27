#include "tcp_scanner.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <random>
#include <netinet/if_ether.h>


/**
 * @brief Computes checksum for given data.
 */
unsigned short TCPScanner::checksum(const void* data, int length) {
    unsigned int sum = 0;
    const unsigned short* ptr = (const unsigned short*)data;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(const unsigned char*)ptr;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

TCPScanner::TCPScanner(const std::string& target_ip, const std::vector<int>& ports, const std::string& interface, int timeout)
    : target_ip(target_ip), ports(ports), interface(interface), timeout(timeout), pcap_handle(nullptr) {}

TCPScanner::~TCPScanner() {
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }
}

/**
 * @brief Sends a TCP SYN packet to a specific port.
 */
void TCPScanner::sendSynPacket(int port) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    struct iphdr ip;
    struct tcphdr tcp;

    // Fill IP header
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip.id = htons(54321);
    ip.frag_off = 0;
    ip.ttl = 255;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = INADDR_ANY;
    ip.daddr = dest.sin_addr.s_addr;

    // Fill TCP header
    tcp.source = htons(12345);
    tcp.dest = htons(port);
    tcp.seq = 0;
    tcp.ack_seq = 0;
    tcp.doff = 5;
    tcp.syn = 1;
    tcp.window = htons(64240);
    tcp.check = 0;
    tcp.urg_ptr = 0;

    struct pseudo_header {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;

    psh.saddr = ip.saddr;
    psh.daddr = ip.daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(packet, &psh, sizeof(struct pseudo_header));
    memcpy(packet + sizeof(struct pseudo_header), &tcp, sizeof(struct tcphdr));

    tcp.check = checksum(packet, sizeof(packet));

    if (sendto(sock, &tcp, sizeof(tcp), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }

    close(sock);
}

/**
 * @brief Configures pcap to capture responses.
 */
void TCPScanner::setupPcap() {
    pcap_handle = pcap_open_live(interface.c_str(), 65536, 1, timeout, errbuf);
    if (!pcap_handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return;
    }

    struct bpf_program fp;
    std::string filter = "tcp and dst port 12345 and src host " + target_ip;
    if (pcap_compile(pcap_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile failed: " << pcap_geterr(pcap_handle) << std::endl;
        return;
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "pcap_setfilter failed: " << pcap_geterr(pcap_handle) << std::endl;
        return;
    }
}

/**
 * @brief Packet handler for processing received TCP responses.
 */
void TCPScanner::packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip->ihl * 4);

    if (tcp->syn && tcp->ack) {
        std::cout << ntohs(tcp->source) << "/tcp open" << std::endl;
    } else if (tcp->rst) {
        std::cout << ntohs(tcp->source) << "/tcp closed" << std::endl;
    }
}

/**
 * @brief Starts the scanning process.
 */
void TCPScanner::scan() {
    setupPcap();

    for (int port : ports) {
        sendSynPacket(port);
    }

    pcap_loop(pcap_handle, 0, packetHandler, nullptr);
}
