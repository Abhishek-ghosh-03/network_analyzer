#include "network_analyzer.h"
#include <string>
#include <algorithm>
#include <cctype>

std::string preprocess_payload(const std::string &payload) {
    std::string cleaned_payload;
    std::copy_if(payload.begin(), payload.end(), std::back_inserter(cleaned_payload), [](unsigned char c) {
        return std::isprint(c) || std::isspace(c);
    });
    // Additional preprocessing steps can be added here
    return cleaned_payload;
}

