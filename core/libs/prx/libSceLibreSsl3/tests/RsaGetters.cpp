#include "prx/libSceLibreSsl3/include/Api.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>

static void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "RSA getter check failed at line %u\n", location.line());
    std::abort();
}

int main() {
    std::array<std::uint64_t, 8> numbers{3, 5, 7, 11, 13, 17, 19, 23};
    const auto pointer = [&](std::size_t index) { return reinterpret_cast<const LibreSsl3Bignum*>(&numbers[index]); };
    const auto* sentinel = pointer(7);
    for (bool populated : {false, true}) {
        LibreSsl3Rsa key{};
        key.references = 19;
        key.flags = 0x123456;
        if (populated) {
            key.n = &numbers[0];
            key.e = &numbers[1];
            key.d = &numbers[2];
            key.p = &numbers[3];
            key.q = &numbers[4];
            key.dmp1 = &numbers[5];
            key.dmq1 = &numbers[6];
            key.iqmp = &numbers[7];
        }
        std::array<unsigned char, sizeof(key)> before{};
        std::memcpy(before.data(), &key, sizeof(key));
        for (unsigned int mask = 0; mask < 8; ++mask) {
            const LibreSsl3Bignum* a = sentinel;
            const LibreSsl3Bignum* b = sentinel;
            const LibreSsl3Bignum* c = sentinel;
            RSA_get0_key_nid_postfix(&key, mask & 1 ? &a : nullptr, mask & 2 ? &b : nullptr, mask & 4 ? &c : nullptr);
            Check(a == ((mask & 1) ? (populated ? pointer(0) : nullptr) : sentinel));
            Check(b == ((mask & 2) ? (populated ? pointer(1) : nullptr) : sentinel));
            Check(c == ((mask & 4) ? (populated ? pointer(2) : nullptr) : sentinel));
            a = b = c = sentinel;
            RSA_get0_crt_params_nid_postfix(&key, mask & 1 ? &a : nullptr, mask & 2 ? &b : nullptr, mask & 4 ? &c : nullptr);
            Check(a == ((mask & 1) ? (populated ? pointer(5) : nullptr) : sentinel));
            Check(b == ((mask & 2) ? (populated ? pointer(6) : nullptr) : sentinel));
            Check(c == ((mask & 4) ? (populated ? pointer(7) : nullptr) : sentinel));
        }
        for (unsigned int mask = 0; mask < 4; ++mask) {
            const LibreSsl3Bignum* a = sentinel;
            const LibreSsl3Bignum* b = sentinel;
            RSA_get0_factors_nid_postfix(&key, mask & 1 ? &a : nullptr, mask & 2 ? &b : nullptr);
            Check(a == ((mask & 1) ? (populated ? pointer(3) : nullptr) : sentinel));
            Check(b == ((mask & 2) ? (populated ? pointer(4) : nullptr) : sentinel));
        }
        const LibreSsl3Bignum* alias = sentinel;
        RSA_get0_key_nid_postfix(&key, &alias, &alias, &alias);
        Check(alias == key.d);
        RSA_get0_factors_nid_postfix(&key, &alias, &alias);
        Check(alias == key.q);
        RSA_get0_crt_params_nid_postfix(&key, &alias, &alias, &alias);
        Check(alias == key.iqmp);
        Check(std::memcmp(&key, before.data(), sizeof(key)) == 0);
    }
    RSA_get0_key_nid_postfix(nullptr, nullptr, nullptr, nullptr);
    RSA_get0_factors_nid_postfix(nullptr, nullptr, nullptr);
    RSA_get0_crt_params_nid_postfix(nullptr, nullptr, nullptr, nullptr);
    for (int selection = 0; selection < 3; ++selection) {
        const LibreSsl3Bignum* output = sentinel;
        bool threw = false;
        try {
            if (selection == 0) RSA_get0_key_nid_postfix(nullptr, &output, nullptr, nullptr);
            if (selection == 1) RSA_get0_factors_nid_postfix(nullptr, &output, nullptr);
            if (selection == 2) RSA_get0_crt_params_nid_postfix(nullptr, &output, nullptr, nullptr);
        } catch (const std::invalid_argument&) { threw = true; }
        Check(threw && output == sentinel);
    }
    Check(numbers == std::array<std::uint64_t, 8>{3, 5, 7, 11, 13, 17, 19, 23});
    std::puts("RSA borrowed-pointer, optional-output, ownership and invalid-input checks passed");
}
