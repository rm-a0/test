#include "arg_parser.h"
#include "tcp_scanner.h"

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    ArgParser parser(argc, argv);
    
    std::string target = parser.getTarget();
    std::vector<int> tcp_ports = parser.getTcpPorts();
    std::string interface = parser.getInterface();
    int timeout = parser.getTimeout();

    // Check if a valid target is provided
    if (target.empty()) {
        std::cerr << "Error: No target specified.\n";
        return EXIT_FAILURE;
    }

    // Check if at least one TCP port is provided
    if (tcp_ports.empty()) {
        std::cerr << "Error: No TCP ports specified.\n";
        return EXIT_FAILURE;
    }

    // Create TCPScanner object and start the scan
    TCPScanner scanner(target, tcp_ports, interface, timeout);
    scanner.scan();

    return EXIT_SUCCESS;
}
