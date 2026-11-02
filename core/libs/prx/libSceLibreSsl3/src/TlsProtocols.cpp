#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include <array>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace {

bool Equal(std::string_view input, std::string_view expected) {
    if (input.size() != expected.size()) return false;
    for (std::size_t index = 0; index < input.size(); ++index) {
        const unsigned char byte = input[index];
        const auto folded = byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
        if (folded != static_cast<unsigned char>(expected[index])) return false;
    }
    return true;
}

std::uint32_t Protocol(std::string_view token) {
    struct Entry { std::string_view name; std::uint32_t mask; };
    constexpr std::array<Entry, 9> entries{{
        {"all", 0x18}, {"legacy", 0x18}, {"default", 0x18}, {"secure", 0x18}, {"tlsv1", 0x18},
        {"tlsv1.0", 0x02}, {"tlsv1.1", 0x04}, {"tlsv1.2", 0x08}, {"tlsv1.3", 0x10}
    }};
    for (const auto& entry : entries)
        if (Equal(token, entry.name)) return entry.mask;
    return 0;
}

} // namespace

extern "C" {

int APS5_VABI tls_config_parse_protocols_nid_postfix(std::uint32_t* protocols, const char* input) {
    std::uint32_t result = 0x18;
    std::unique_ptr<char, decltype(&free_nid_postfix)> copy(nullptr, free_nid_postfix);
    if (input) {
        copy.reset(strdup_nid_postfix(input));
        if (!copy) return -1;
        result = 0;
        std::string_view remaining(copy.get());
        for (;;) {
            const auto separator = remaining.find_first_of(",:");
            auto token = remaining.substr(0, separator);
            const auto start = token.find_first_not_of(" \t");
            token.remove_prefix(start == std::string_view::npos ? token.size() : start);
            const bool negate = token.starts_with('!');
            if (negate) {
                token.remove_prefix(1);
                if (!result) result = 0x18;
            }
            const auto mask = Protocol(token);
            if (!mask) return -1;
            result = negate ? result & ~mask : result | mask;
            if (separator == std::string_view::npos) break;
            remaining.remove_prefix(separator + 1);
        }
    }
    if (!protocols) throw std::invalid_argument("tls_config_parse_protocols: null output");
    *protocols = result;
    return 0;
}

}
