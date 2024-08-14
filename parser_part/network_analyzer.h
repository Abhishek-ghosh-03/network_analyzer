#ifndef NETWORK_ANALYZER_H
#define NETWORK_ANALYZER_H

#include <string>

std::string preprocess_payload(const std::string &payload);
std::string packet_to_json(const u_char *packet);
void send_json_over_network(const std::string &json_data, const char *dest_ip, int port);

#endif // NETWORK_ANALYZER_H

