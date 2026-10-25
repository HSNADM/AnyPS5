#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"

#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <thread>
#include <vector>

using namespace LibreSsl;

static void Check(bool value, int line) {
    if (!value) {
        std::fprintf(stderr, "RSA check failed at line %d\n", line);
        std::abort();
    }
}
#define Require(value) Check((value), __LINE__)

static int Random(void* state, unsigned char* output, std::size_t size) {
    auto& value = *static_cast<std::uint64_t*>(state);
    for (std::size_t index = 0; index < size; ++index) {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        output[index] = static_cast<unsigned char>(value);
    }
    return 0;
}

static RsaNumber* GuestNumber(const mbedtls_mpi& number) {
    auto* result = static_cast<RsaNumber*>(calloc_nid_postfix(1, sizeof(RsaNumber)));
    Require(result);
    result->top = result->capacity = static_cast<int>((mbedtls_mpi_size(&number) + 7) / 8);
    result->flags = 1;
    result->words = static_cast<std::uint64_t*>(calloc_nid_postfix(result->capacity, 8));
    Require(result->words);
    Require(mbedtls_mpi_write_binary_le(&number, reinterpret_cast<unsigned char*>(result->words), result->capacity * 8) == 0);
    return result;
}

struct Fixture {
    mbedtls_rsa_context native;
    RsaKey* guest;
    std::uint64_t random = 0x1489365fabce287d;

    Fixture() : guest(RSA_new_nid_postfix()) {
        Require(guest);
        mbedtls_rsa_init(&native);
        Require(mbedtls_rsa_gen_key(&native, Random, &random, 1024, 65537) == 0);
        std::array<mbedtls_mpi, 8> numbers;
        for (auto& number : numbers) mbedtls_mpi_init(&number);
        Require(mbedtls_rsa_export(&native, &numbers[0], &numbers[3], &numbers[4], &numbers[2], &numbers[1]) == 0);
        Require(mbedtls_rsa_export_crt(&native, &numbers[5], &numbers[6], &numbers[7]) == 0);
        std::array<RsaNumber**, 8> targets{&guest->n, &guest->e, &guest->d, &guest->p, &guest->q, &guest->dp, &guest->dq, &guest->inverseQ};
        for (std::size_t index = 0; index < numbers.size(); ++index) {
            *targets[index] = GuestNumber(numbers[index]);
            mbedtls_mpi_free(&numbers[index]);
        }
    }

    ~Fixture() {
        RSA_free_nid_postfix(guest);
        mbedtls_rsa_free(&native);
    }
};

static void Raw() {
    auto* key = RSA_new_nid_postfix();
    Require(key);
    const std::array<std::uint64_t, 8> values{3233, 17, 2753, 61, 53, 53, 49, 38};
    std::array<RsaNumber**, 8> targets{&key->n, &key->e, &key->d, &key->p, &key->q, &key->dp, &key->dq, &key->inverseQ};
    for (std::size_t index = 0; index < values.size(); ++index) {
        mbedtls_mpi number;
        mbedtls_mpi_init(&number);
        Require(mbedtls_mpi_read_binary_le(&number, reinterpret_cast<const unsigned char*>(&values[index]), 8) == 0);
        *targets[index] = GuestNumber(number);
        mbedtls_mpi_free(&number);
    }
    const std::array<unsigned char, 2> message{0, 65};
    std::array<unsigned char, 2> cipher{}, plain{}, signature{};
    Require(RSA_public_encrypt_nid_postfix(2, message.data(), cipher.data(), key, 3) == 2);
    Require(cipher[0] == 0x0a && cipher[1] == 0xe6);
    Require(RSA_private_decrypt_nid_postfix(2, cipher.data(), plain.data(), key, 3) == 2);
    Require(plain == message);
    Require(RSA_private_encrypt_nid_postfix(2, message.data(), signature.data(), key, 3) == 2);
    Require(signature[0] == 0x02 && signature[1] == 0x4c);
    Require(RSA_public_decrypt_nid_postfix(2, signature.data(), plain.data(), key, 3) == 2);
    Require(plain == message);
    Require(RSA_check_key_nid_postfix(key) == 1);
    Require(RSA_up_ref_nid_postfix(key) == 1 && key->references == 2);
    RSA_free_nid_postfix(key);
    Require(key->references == 1);
    RSA_free_nid_postfix(key);

    Fixture fixture;
    std::array<unsigned char, 128> input{}, expected{}, actual{}, recovered{};
    input.back() = 42;
    Require(mbedtls_rsa_public(&fixture.native, input.data(), expected.data()) == 0);
    Require(RSA_public_encrypt_nid_postfix(128, input.data(), actual.data(), fixture.guest, 3) == 128);
    Require(actual == expected);
    Require(RSA_private_decrypt_nid_postfix(128, actual.data(), recovered.data(), fixture.guest, 3) == 128);
    Require(recovered == input);
    Require(RSA_public_encrypt_nid_postfix(128, input.data(), input.data(), fixture.guest, 3) == 128);
    Require(input == expected);
    Require(RSA_private_decrypt_nid_postfix(128, input.data(), input.data(), fixture.guest, 3) == 128);
    Require(input.back() == 42 && std::all_of(input.begin(), input.end() - 1, [](unsigned char byte) { return byte == 0; }));
    auto* e = fixture.guest->e;
    fixture.guest->e = nullptr;
    fixture.guest->flags |= 0x80;
    Require(RSA_private_decrypt_nid_postfix(128, expected.data(), input.data(), fixture.guest, 3) == 128 && input.back() == 42);
    fixture.guest->flags &= ~0x80;
    Require(RSA_private_decrypt_nid_postfix(128, expected.data(), input.data(), fixture.guest, 3) == 128 && input.back() == 42);
    fixture.guest->e = e;
    auto* d = fixture.guest->d;
    fixture.guest->d = nullptr;
    Require(RSA_private_decrypt_nid_postfix(128, expected.data(), input.data(), fixture.guest, 3) == 128 && input.back() == 42);
    fixture.guest->d = d;
    auto* p = fixture.guest->p;
    auto* q = fixture.guest->q;
    fixture.guest->p = fixture.guest->q = nullptr;
    Require(RSA_private_decrypt_nid_postfix(128, expected.data(), input.data(), fixture.guest, 3) == 128 && input.back() == 42);
    fixture.guest->p = p;
    fixture.guest->q = q;

    auto* large = RSA_new_nid_postfix();
    mbedtls_mpi modulus, exponent;
    mbedtls_mpi_init(&modulus);
    mbedtls_mpi_init(&exponent);
    Require(mbedtls_mpi_set_bit(&modulus, 16383, 1) == 0);
    Require(mbedtls_mpi_add_int(&modulus, &modulus, 0x12345) == 0);
    Require(mbedtls_mpi_lset(&exponent, 3) == 0);
    large->n = GuestNumber(modulus);
    large->e = GuestNumber(exponent);
    std::vector<unsigned char> largeInput(2048), largeOutput(2048);
    largeInput.back() = 65;
    for (const auto operation : {RSA_public_encrypt_nid_postfix, RSA_public_decrypt_nid_postfix}) {
        Require(operation(2048, largeInput.data(), largeOutput.data(), large, 3) == 2048);
        Require(std::all_of(largeOutput.begin(), largeOutput.end() - 3, [](unsigned char byte) { return byte == 0; }));
        Require(largeOutput[2045] == 4 && largeOutput[2046] == 0x30 && largeOutput[2047] == 0xc1);
    }
    RSA_free_nid_postfix(large);
    mbedtls_mpi_free(&modulus);
    mbedtls_mpi_free(&exponent);
}

static void Padding() {
    Fixture fixture;
    std::array<unsigned char, 128> cipher{}, decoded{}, padded{};
    for (const int padding : {1, 4}) {
        Require(mbedtls_rsa_set_padding(&fixture.native, padding == 1 ? MBEDTLS_RSA_PKCS_V15 : MBEDTLS_RSA_PKCS_V21, padding == 1 ? MBEDTLS_MD_NONE : MBEDTLS_MD_SHA1) == 0);
        const int maximum = padding == 1 ? 117 : 86;
        for (const int length : {0, 1, 32, maximum}) {
            std::vector<unsigned char> message(length, 0x93);
            Require(RSA_public_encrypt_nid_postfix(length, message.data(), cipher.data(), fixture.guest, padding) == 128);
            std::size_t actual = 999;
            Require(mbedtls_rsa_pkcs1_decrypt(&fixture.native, Random, &fixture.random, &actual, cipher.data(), decoded.data(), decoded.size()) == 0);
            Require(actual == message.size() && std::equal(message.begin(), message.end(), decoded.begin()));
            Require(mbedtls_rsa_pkcs1_encrypt(&fixture.native, Random, &fixture.random, message.size(), message.data(), cipher.data()) == 0);
            decoded.fill(0xa5);
            Require(RSA_private_decrypt_nid_postfix(128, cipher.data(), decoded.data(), fixture.guest, padding) == length);
            Require(std::equal(message.begin(), message.end(), decoded.begin()));
            Require(decoded[length] == 0xa5);
        }
    }
    const std::array<unsigned char, 5> message{1, 2, 3, 4, 5};
    for (const int padding : {1, 5}) {
        Require(RSA_private_encrypt_nid_postfix(message.size(), message.data(), cipher.data(), fixture.guest, padding) == 128);
        Require(RSA_public_decrypt_nid_postfix(128, cipher.data(), decoded.data(), fixture.guest, padding) == static_cast<int>(message.size()));
        Require(std::equal(message.begin(), message.end(), decoded.begin()));
    }
    Require(RSA_private_encrypt_nid_postfix(message.size(), message.data(), cipher.data(), fixture.guest, 1) == 128);
    Require(mbedtls_rsa_public(&fixture.native, cipher.data(), padded.data()) == 0);
    Require(padded[0] == 0 && padded[1] == 1);
    Require(std::all_of(padded.begin() + 2, padded.end() - 6, [](unsigned char byte) { return byte == 255; }));
    Require(padded[122] == 0);
    Require(std::equal(message.begin(), message.end(), padded.end() - 5));
    Require(RSA_public_encrypt_nid_postfix(message.size(), message.data(), cipher.data(), fixture.guest, 2) == 128);
    decoded.fill(0xa5);
    ERR_clear_error_nid_postfix();
    Require(RSA_private_decrypt_nid_postfix(128, cipher.data(), decoded.data(), fixture.guest, 2) == -1);
    Require((ERR_get_error_nid_postfix() & 0xfff) == 115);
    Require(std::all_of(decoded.begin(), decoded.end(), [](unsigned char byte) { return byte == 0xa5; }));
    Require(mbedtls_rsa_private(&fixture.native, Random, &fixture.random, cipher.data(), padded.data()) == 0);
    padded[121] = 4;
    Require(mbedtls_rsa_public(&fixture.native, padded.data(), cipher.data()) == 0);
    Require(RSA_private_decrypt_nid_postfix(128, cipher.data(), decoded.data(), fixture.guest, 2) == 5);
    Require(std::equal(message.begin(), message.end(), decoded.begin()));
}

static int finished = 0;

static int APS5_VABI CustomOperation_nid_no_patch(int length, const unsigned char*, unsigned char* output, RsaKey*, int padding) {
    output[0] = static_cast<unsigned char>(padding);
    return length + 17;
}

static int APS5_VABI CustomFinish_nid_no_patch(RsaKey*) {
    ++finished;
    return 1;
}

static void Ownership() {
    RSA_free_nid_postfix(nullptr);
    auto* key = RSA_new_nid_postfix();
    Require(key && key->references == 1 && key->flags == 6 && !key->n);
    RsaMethod method = *key->method;
    method.publicEncrypt = method.publicDecrypt = method.privateEncrypt = method.privateDecrypt = CustomOperation_nid_no_patch;
    method.finish = CustomFinish_nid_no_patch;
    key->method = &method;
    for (const auto operation : {RSA_public_encrypt_nid_postfix, RSA_public_decrypt_nid_postfix, RSA_private_encrypt_nid_postfix, RSA_private_decrypt_nid_postfix}) {
        unsigned char result = 0;
        Require(operation(2, nullptr, &result, key, 7) == 19 && result == 7);
    }
    Require(RSA_up_ref_nid_postfix(key) == 1);
    RSA_free_nid_postfix(key);
    Require(finished == 0 && key->references == 1);
    RSA_free_nid_postfix(key);
    Require(finished == 1);
    auto* shared = RSA_new_nid_postfix();
    std::array<std::thread, 4> workers;
    for (auto& worker : workers) worker = std::thread([&] {
        for (int index = 0; index < 1000; ++index) {
            Require(RSA_up_ref_nid_postfix(shared) == 1);
            RSA_free_nid_postfix(shared);
        }
    });
    for (auto& worker : workers) worker.join();
    Require(shared->references == 1);
    RSA_free_nid_postfix(shared);
    std::uint64_t staticWord = 37;
    RsaNumber staticNumber{&staticWord, 1, 1, 0, 2};
    auto* staticKey = RSA_new_nid_postfix();
    staticKey->n = &staticNumber;
    RSA_free_nid_postfix(staticKey);
    Require(staticWord == 37 && staticNumber.words == nullptr && staticNumber.flags == 0);
    for (int index = 0; index < 256; ++index) RSA_free_nid_postfix(RSA_new_nid_postfix());
}

static void Invalid() {
    Fixture fixture;
    std::array<unsigned char, 129> input{}, output{};
    for (const auto operation : {RSA_public_encrypt_nid_postfix, RSA_private_encrypt_nid_postfix}) {
        for (const int length : {-1, 127, 129}) {
            output.fill(0xa5);
            Require(operation(length, input.data(), output.data(), fixture.guest, 3) == -1);
            Require(std::all_of(output.begin(), output.end(), [](unsigned char byte) { return byte == 0xa5; }));
        }
        Require(operation(1, input.data(), output.data(), fixture.guest, 999) == -1);
    }
    for (const auto operation : {RSA_public_decrypt_nid_postfix, RSA_private_decrypt_nid_postfix}) {
        Require(operation(129, input.data(), output.data(), fixture.guest, 1) == -1);
        Require(operation(-1, input.data(), output.data(), fixture.guest, 1) == -1);
        Require(operation(128, input.data(), output.data(), fixture.guest, 1) == -1);
    }
    Require(RSA_check_key_nid_postfix(fixture.guest) == 1);
    for (const auto [number, reason] : {std::pair{fixture.guest->n, 127}, {fixture.guest->dp, 124}, {fixture.guest->dq, 125}, {fixture.guest->inverseQ, 126}}) {
        number->words[0] ^= 2;
        ERR_clear_error_nid_postfix();
        Require(RSA_check_key_nid_postfix(fixture.guest) == 0);
        Require((ERR_get_error_nid_postfix() & 0xfff) == static_cast<unsigned int>(reason));
        number->words[0] ^= 2;
    }
    auto* missing = fixture.guest->d;
    fixture.guest->d = nullptr;
    ERR_clear_error_nid_postfix();
    Require(RSA_check_key_nid_postfix(fixture.guest) == 0);
    Require((ERR_get_error_nid_postfix() & 0xfff) == 147);
    fixture.guest->d = missing;
}

int main(int argc, char** argv) {
    void* const heapApi[10]{};
    ApplicationHeapRegister_nid_no_patch(heapApi);
    Require(argc == 2);
    const std::string_view selection(argv[1]);
    if (selection == "raw") Raw();
    else if (selection == "padding") Padding();
    else if (selection == "ownership") Ownership();
    else if (selection == "invalid") Invalid();
    else Require(false);
}
