#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <vector>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/**
 * @class TCPScanner
 * @brief Performs TCP SYN scans using raw sockets.
 */
class TCPScanner {
private:
    std::string target_ip;      ///< Target IP address
    std::vector<int> ports;     ///< List of TCP ports to scan
    std::string interface;      ///< Network interface to use
    int timeout;                ///< Timeout for response in milliseconds
    pcap_t* pcap_handle;        ///< libpcap handle
    char errbuf[PCAP_ERRBUF_SIZE]; ///< Buffer for pcap errors

    /**
     * @brief Sends a TCP SYN packet to a specific port.
     * @param port Port number to send SYN packet to.
     */
    void sendSynPacket(int port);

    /**
     * @brief Initializes pcap for capturing responses.
     */
    void setupPcap();

    /**
     * @brief Handles incoming packets to determine port status.
     * @param user_data User data (not used).
     * @param pkthdr Packet header.
     * @param packet Raw packet data.
     */
    static void packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    /**
     * @brief Calculates checksum for IP/TCP headers.
     * @param data Pointer to the data to compute checksum for.
     * @param length Length of the data.
     * @return Computed checksum.
     */
    static unsigned short checksum(const void* data, int length);

public:
    /**
     * @brief Constructor for TCPScanner.
     * @param target_ip Target IP address.
     * @param ports List of TCP ports to scan.
     * @param interface Network interface.
     * @param timeout Timeout in milliseconds.
     */
    TCPScanner(const std::string& target_ip, const std::vector<int>& ports, const std::string& interface, int timeout);

    /**
     * @brief Destructor for TCPScanner.
     */
    ~TCPScanner();

    /**
     * @brief Starts the scanning process.
     */
    void scan();
};

#endif // TCP_SCANNER_H
