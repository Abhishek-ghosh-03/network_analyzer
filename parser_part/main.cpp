#include <iostream>
#include <pcap.h>
#include "network_analyzer.h"
#include <nlohmann/json.hpp>

// Packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    std::string json_data = packet_to_json(packet);
    send_json_over_network(json_data, "192.168.116.224", 12345);  // Example destination IP and port
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the default device for live capture
    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 1;
    }

    // Capture packets and process each using the packet_handler
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}

