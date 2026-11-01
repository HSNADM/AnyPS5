#include "prx/libSceLibreSsl3/include/Api.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

extern "C" int APS5_VABI AES_unwrap_key_nid_postfix(AesKey* key, const unsigned char* iv, unsigned char* output, const unsigned char* input, unsigned int length) {
    if (length < 24 || length % 8 != 0) return -1;
    if (!key || !output || !input) throw std::invalid_argument("AES_unwrap_key: null key, input or output");
    if (key->rounds != 10 && key->rounds != 12 && key->rounds != 14) throw std::invalid_argument("AES_unwrap_key: invalid key rounds");
    const unsigned int size = length - 8;
    const unsigned int blocks = size / 8;
    std::array<unsigned char, 16> state;
    std::memcpy(state.data(), input, 8);
    std::memmove(output, input + 8, size);
    std::uint32_t counter = blocks * 6;
    for (unsigned int round = 0; round < 6; ++round) {
        for (unsigned int block = blocks; block != 0; --block, --counter) {
            for (unsigned int byte = 0; byte < 4; ++byte) state[7 - byte] ^= static_cast<unsigned char>(counter >> (8 * byte));
            auto* current = output + (block - 1) * 8;
            std::memcpy(state.data() + 8, current, 8);
            AES_decrypt_nid_postfix(state.data(), state.data(), key);
            std::memcpy(current, state.data() + 8, 8);
        }
    }
    constexpr std::array<unsigned char, 8> defaultIv{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
    const bool valid = std::memcmp(state.data(), iv ? iv : defaultIv.data(), 8) == 0;
    auto* temporary = static_cast<volatile unsigned char*>(state.data());
    for (unsigned int index = 0; index < state.size(); ++index) temporary[index] = 0;
    if (!valid) {
        auto* bytes = static_cast<volatile unsigned char*>(output);
        for (unsigned int index = 0; index < size; ++index) bytes[index] = 0;
        return 0;
    }
    return static_cast<int>(size);
}
