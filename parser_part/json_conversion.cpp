#include "network_analyzer.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <string>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

std::string packet_to_json(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    nlohmann::json packet_data;
    packet_data["src_ip"] = src_ip;
    packet_data["dst_ip"] = dst_ip;
    packet_data["protocol"] = ip_header->ip_p;
    packet_data["length"] = ntohs(ip_header->ip_len);

    int header_len = 14 + ip_header->ip_hl * 4;
    int payload_len = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4;
    if (payload_len > 0) {
        const u_char *payload = packet + header_len;
        std::string raw_payload(reinterpret_cast<const char*>(payload), payload_len);
        
        // Preprocess the payload
        std::string preprocessed_payload = preprocess_payload(raw_payload);

        // Convert the preprocessed payload to a hex string
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (char c : preprocessed_payload) {
            ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }

        packet_data["payload"] = ss.str();  // Store the preprocessed payload
    } else {
        packet_data["payload"] = "";
    }

    return packet_data.dump();  // Return the JSON string
}

