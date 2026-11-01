#include "prx/libSceLibreSsl3/include/Api.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>
#include <string_view>
#include <vector>

using Bytes = std::vector<unsigned char>;

static void Check(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "AES unwrap check failed at line %u\n", location.line());
    std::abort();
}

static Bytes Hex(std::string_view text) {
    Check(text.size() % 2 == 0);
    Bytes bytes;
    const auto digit = [](char value) -> unsigned { return value <= '9' ? value - '0' : value - 'A' + 10; };
    for (std::size_t index = 0; index < text.size(); index += 2) bytes.push_back(static_cast<unsigned char>((digit(text[index]) << 4) | digit(text[index + 1])));
    return bytes;
}

static Bytes Wrap(const Bytes& rawKey, const Bytes& plaintext, const std::array<unsigned char, 8>& iv) {
    AesKey key{};
    Check(AES_set_encrypt_key_nid_postfix(rawKey.data(), static_cast<int>(rawKey.size() * 8), &key) == 0);
    Bytes result(iv.begin(), iv.end());
    result.insert(result.end(), plaintext.begin(), plaintext.end());
    const auto blocks = plaintext.size() / 8;
    std::array<unsigned char, 16> block{};
    std::uint64_t counter = 1;
    for (int round = 0; round < 6; ++round) {
        for (std::size_t index = 1; index <= blocks; ++index, ++counter) {
            std::copy_n(result.begin(), 8, block.begin());
            std::copy_n(result.begin() + index * 8, 8, block.begin() + 8);
            AES_encrypt_nid_postfix(block.data(), block.data(), &key);
            for (unsigned int byte = 0; byte < 8; ++byte) result[byte] = block[byte] ^ static_cast<unsigned char>(counter >> ((7 - byte) * 8));
            std::copy_n(block.begin() + 8, 8, result.begin() + index * 8);
        }
    }
    return result;
}

static void Vector(std::string_view keyHex, std::string_view plainHex, std::string_view wrappedHex) {
    const auto rawKey = Hex(keyHex);
    const auto plain = Hex(plainHex);
    const auto wrapped = Hex(wrappedHex);
    AesKey key{};
    Check(AES_set_decrypt_key_nid_postfix(rawKey.data(), static_cast<int>(rawKey.size() * 8), &key) == 0);
    Bytes output(plain.size() + 16, 0x5a);
    Check(AES_unwrap_key_nid_postfix(&key, nullptr, output.data() + 8, wrapped.data(), static_cast<unsigned int>(wrapped.size())) == static_cast<int>(plain.size()));
    Check(std::equal(plain.begin(), plain.end(), output.begin() + 8));
    Check(std::all_of(output.begin(), output.begin() + 8, [](auto byte) { return byte == 0x5a; }));
    Check(std::all_of(output.end() - 8, output.end(), [](auto byte) { return byte == 0x5a; }));
    const std::array<unsigned char, 8> iv{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
    Check(Wrap(rawKey, plain, iv) == wrapped);
    Check(AES_unwrap_key_nid_postfix(&key, iv.data(), output.data(), wrapped.data(), static_cast<unsigned int>(wrapped.size())) == static_cast<int>(plain.size()));
    for (int shift : {-7, -1, 0, 1, 7, 8}) {
        Bytes overlap(wrapped.size() + 32, 0x5a);
        std::copy(wrapped.begin(), wrapped.end(), overlap.begin() + 8);
        Check(AES_unwrap_key_nid_postfix(&key, nullptr, overlap.data() + 8 + shift, overlap.data() + 8, static_cast<unsigned int>(wrapped.size())) == static_cast<int>(plain.size()));
        Check(std::equal(plain.begin(), plain.end(), overlap.begin() + 8 + shift));
    }
    for (std::size_t index = 0; index < wrapped.size(); ++index) {
        auto tampered = wrapped;
        tampered[index] ^= 0x80;
        std::fill(output.begin(), output.end(), 0x5a);
        Check(AES_unwrap_key_nid_postfix(&key, nullptr, output.data() + 8, tampered.data(), static_cast<unsigned int>(tampered.size())) == 0);
        Check(std::all_of(output.begin() + 8, output.end() - 8, [](auto byte) { return byte == 0; }));
        Check(output.front() == 0x5a && output.back() == 0x5a);
    }
}

int main() {
    Vector("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    Vector("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
    Vector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
    Vector("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2");
    Vector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");
    Vector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
    for (unsigned int size = 0; size < 64; ++size) {
        if (size >= 24 && size % 8 == 0) continue;
        Check(AES_unwrap_key_nid_postfix(nullptr, nullptr, nullptr, nullptr, size) == -1);
    }
    const auto rawKey = Hex("000102030405060708090A0B0C0D0E0F");
    const std::array<unsigned char, 8> iv{1, 3, 5, 7, 9, 11, 13, 15};
    Bytes plain(640);
    for (std::size_t index = 0; index < plain.size(); ++index) plain[index] = static_cast<unsigned char>(index);
    const auto wrapped = Wrap(rawKey, plain, iv);
    AesKey key{};
    Check(AES_set_decrypt_key_nid_postfix(rawKey.data(), 128, &key) == 0);
    Bytes output(plain.size(), 0x5a);
    Check(AES_unwrap_key_nid_postfix(&key, iv.data(), output.data(), wrapped.data(), static_cast<unsigned int>(wrapped.size())) == static_cast<int>(plain.size()));
    Check(output == plain);
    Check(AES_unwrap_key_nid_postfix(&key, nullptr, output.data(), wrapped.data(), static_cast<unsigned int>(wrapped.size())) == 0);
    Check(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0; }));
    for (int invalid = 0; invalid < 4; ++invalid) {
        std::fill(output.begin(), output.end(), 0x5a);
        key.rounds = invalid == 3 ? 9 : 10;
        bool threw = false;
        try {
            AES_unwrap_key_nid_postfix(invalid == 0 ? nullptr : &key, nullptr, invalid == 1 ? nullptr : output.data(), invalid == 2 ? nullptr : wrapped.data(), 24);
        } catch (const std::invalid_argument&) { threw = true; }
        Check(threw);
        Check(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0x5a; }));
    }
    std::puts("AES unwrap RFC vectors, overlap, integrity and input checks passed");
}
