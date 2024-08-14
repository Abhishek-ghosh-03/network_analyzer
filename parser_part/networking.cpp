#include "network_analyzer.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // For inet_pton
#include <unistd.h>     // For close()

void send_json_over_network(const std::string &json_data, const char *dest_ip, int port) {
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip, &servaddr.sin_addr) <= 0) {
        std::cerr << "Invalid address or Address not supported" << std::endl;
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "Connection to the server failed" << std::endl;
        close(sockfd);
        return;
    }

    send(sockfd, json_data.c_str(), json_data.size(), 0);
    close(sockfd);
}

