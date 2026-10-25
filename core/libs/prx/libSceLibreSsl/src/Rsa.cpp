#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/HostEntropy.hpp"

#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace LibreSsl;

namespace {

constexpr int Pkcs1 = 1;
constexpr int Sslv23 = 2;
constexpr int NoPadding = 3;
constexpr int Oaep = 4;
constexpr int X931 = 5;
constexpr int NoBlinding = 0x80;

struct ArithmeticError {};

struct Buffer : std::vector<unsigned char> {
    using std::vector<unsigned char>::vector;
    ~Buffer() {
        auto* bytes = static_cast<volatile unsigned char*>(data());
        for (std::size_t index = 0; index < size(); ++index) bytes[index] = 0;
    }
};

int Error(int reason) {
    LibreSslPutError_nid_no_patch(4, 0, reason);
    return -1;
}

void Require(int result) {
    if (result != 0) throw ArithmeticError{};
}

struct Number {
    mbedtls_mpi value;

    Number() { mbedtls_mpi_init(&value); }
    explicit Number(const RsaNumber* number) : Number() {
        if (!number || number->top < 0 || number->capacity < number->top || (number->top && !number->words)) {
            throw std::invalid_argument("RSA: invalid BIGNUM");
        }
        Require(mbedtls_mpi_read_binary_le(&value, reinterpret_cast<const unsigned char*>(number->words), static_cast<std::size_t>(number->top) * 8));
        if (number->negative) {
            Number zero;
            Require(mbedtls_mpi_sub_mpi(&value, &zero.value, &value));
        }
    }
    ~Number() { mbedtls_mpi_free(&value); }
    Number(const Number&) = delete;
    Number& operator=(const Number&) = delete;
};

struct Context {
    mbedtls_rsa_context value;
    Context() { mbedtls_rsa_init(&value); }
    ~Context() { mbedtls_rsa_free(&value); }
};

int Random(void*, unsigned char* bytes, std::size_t size) {
    HostEntropy_nid_no_patch(bytes, size);
    return 0;
}

std::size_t Size(const RsaKey* key) {
    if (!key) throw std::invalid_argument("RSA: null key");
    Number n(key->n);
    return mbedtls_mpi_size(&n.value);
}

const RsaMethod defaultMethod{
    "Eric Young's PKCS#1 RSA", RSA_public_encrypt_nid_postfix, RSA_public_decrypt_nid_postfix,
    RSA_private_encrypt_nid_postfix, RSA_private_decrypt_nid_postfix,
    nullptr, nullptr, nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr
};

RsaOperation Custom(RsaKey* key, bool privateKey, bool encrypt) {
    if (!key || !key->method) throw std::invalid_argument("RSA: null key or method");
    if (key->method == &defaultMethod) return nullptr;
    const auto operation = privateKey
        ? (encrypt ? key->method->privateEncrypt : key->method->privateDecrypt)
        : (encrypt ? key->method->publicEncrypt : key->method->publicDecrypt);
    if (!operation) throw std::invalid_argument("RSA: missing method callback");
    return operation;
}

bool Sha1(const unsigned char* bytes, std::size_t size, unsigned char* digest) {
    return mbedtls_sha1(bytes, size, digest) == 0;
}

void Mask(unsigned char* target, std::size_t size, const unsigned char* seed, std::size_t seedSize) {
    Buffer input(seed, seed + seedSize);
    input.resize(seedSize + 4);
    for (std::uint32_t counter = 0; size; ++counter) {
        for (int byte = 0; byte < 4; ++byte) input[seedSize + byte] = static_cast<unsigned char>(counter >> (24 - 8 * byte));
        unsigned char digest[20];
        if (!Sha1(input.data(), input.size(), digest)) throw std::runtime_error("RSA: SHA-1 failed");
        const auto count = std::min(size, sizeof(digest));
        for (std::size_t index = 0; index < count; ++index) target[index] ^= digest[index];
        target += count;
        size -= count;
    }
}

bool Encode(std::vector<unsigned char>& block, const unsigned char* input, int length, int padding, bool privateKey) {
    const std::size_t size = block.size();
    if (length < 0) return Error(110), false;
    const auto count = static_cast<std::size_t>(length);
    if (padding == NoPadding) {
        if (count > size) return Error(110), false;
        if (count < size) return Error(122), false;
        if (count) std::memcpy(block.data(), input, count);
        return true;
    }
    if (padding == X931 && privateKey) {
        if (size < 2 || count > size - 2) return Error(110), false;
        const std::size_t pad = size - count - 2;
        block[0] = pad ? 0x6b : 0x6a;
        if (pad) {
            std::fill(block.begin() + 1, block.begin() + pad, 0xbb);
            block[pad] = 0xba;
        }
        if (count) std::memcpy(block.data() + pad + 1, input, count);
        block.back() = 0xcc;
        return true;
    }
    if (padding == Oaep && !privateKey) {
        if (size < 42 || count > size - 42) return Error(110), false;
        auto* seed = block.data() + 1;
        auto* data = seed + 20;
        if (!Sha1(nullptr, 0, data)) throw std::runtime_error("RSA: SHA-1 failed");
        data[size - count - 22] = 1;
        if (count) std::memcpy(block.data() + size - count, input, count);
        Random(nullptr, seed, 20);
        Mask(data, size - 21, seed, 20);
        Mask(seed, 20, data, size - 21);
        return true;
    }
    if (padding != Pkcs1 && !(padding == Sslv23 && !privateKey)) return Error(118), false;
    if (size < 11 || count > size - 11) return Error(110), false;
    block[1] = privateKey ? 1 : 2;
    const auto padEnd = size - count - 1;
    if (privateKey) {
        std::fill(block.begin() + 2, block.begin() + padEnd, 0xff);
    } else {
        Random(nullptr, block.data() + 2, padEnd - 2);
        for (std::size_t index = 2; index < padEnd; ++index) {
            while (!block[index]) Random(nullptr, &block[index], 1);
        }
        if (padding == Sslv23) std::fill(block.begin() + padEnd - 8, block.begin() + padEnd, 3);
    }
    if (count) std::memcpy(block.data() + size - count, input, count);
    return true;
}

int Decode(std::vector<unsigned char>& block, int padding, bool privateKey) {
    const std::size_t size = block.size();
    if (padding == NoPadding) return 0;
    if (padding == Oaep && privateKey) {
        if (size < 42) return Error(121);
        auto* seed = block.data() + 1;
        auto* data = seed + 20;
        Mask(seed, 20, data, size - 21);
        Mask(data, size - 21, seed, 20);
        unsigned char emptyHash[20];
        if (!Sha1(nullptr, 0, emptyHash)) throw std::runtime_error("RSA: SHA-1 failed");
        unsigned int bad = block[0];
        for (std::size_t index = 0; index < 20; ++index) bad |= data[index] ^ emptyHash[index];
        std::size_t delimiter = size;
        unsigned int found = 0;
        for (std::size_t index = 41; index < size; ++index) {
            const unsigned int first = (found == 0);
            const unsigned int isOne = block[index] == 1;
            bad |= first & (block[index] != 0) & (isOne == 0);
            if (first && isOne) delimiter = index;
            found |= isOne;
        }
        if (bad || !found) return Error(121);
        return static_cast<int>(delimiter + 1);
    }
    if (padding == X931 && !privateKey) {
        if (size < 2 || (block[0] != 0x6a && block[0] != 0x6b)) return Error(137);
        std::size_t first = 1;
        if (block[0] == 0x6b) {
            while (first < size - 1 && block[first] == 0xbb) ++first;
            if (first <= 1 || first >= size - 1 || block[first] != 0xba) return Error(138);
            ++first;
        }
        if (block.back() != 0xcc) return Error(139);
        block.pop_back();
        return static_cast<int>(first);
    }
    if (padding != Pkcs1 && !(padding == Sslv23 && privateKey)) return Error(118);
    if (padding == Sslv23 && size < 11) return Error(111);
    if (size < 2 || block[0] != 0 || block[1] != (privateKey ? 2 : 1)) return Error(privateKey ? 107 : 106);
    std::size_t delimiter = size;
    unsigned int bad = 0;
    unsigned int found = 0;
    for (std::size_t index = 2; index < size; ++index) {
        const unsigned int isZero = block[index] == 0;
        if (!found && isZero) delimiter = index;
        if (!privateKey && !found && !isZero) bad |= block[index] ^ 0xff;
        found |= isZero;
    }
    if (!found) return Error(113);
    if (bad) return Error(102);
    if (delimiter < 10) return Error(padding == Sslv23 ? 113 : 103);
    if (padding == Sslv23 && std::all_of(block.begin() + delimiter - 8, block.begin() + delimiter, [](unsigned char byte) { return byte == 3; })) return Error(115);
    return static_cast<int>(delimiter + 1);
}

bool Transform(std::vector<unsigned char>& block, RsaKey* key, bool privateKey) {
    const RsaNumber zero{};
    Number n(key->n), e(key->e ? key->e : &zero);
    Number value;
    Require(mbedtls_mpi_read_binary(&value.value, block.data(), block.size()));
    if (mbedtls_mpi_cmp_mpi(&value.value, &n.value) >= 0) return Error(132), false;
    if (!privateKey) {
        Number result;
        if (mbedtls_mpi_exp_mod(&result.value, &value.value, &e.value, &n.value, nullptr) != 0) return Error(3), false;
        Require(mbedtls_mpi_write_binary(&result.value, block.data(), block.size()));
        return true;
    }
    if (block.size() > MBEDTLS_MPI_MAX_SIZE) throw std::runtime_error("RSA: private modulus exceeds the bundled mbedtls limit");
    Number d(key->d ? key->d : &zero), p(key->p ? key->p : &zero), q(key->q ? key->q : &zero);
    if (!key->e && (key->flags & NoBlinding)) {
        Number result;
        Require(mbedtls_mpi_exp_mod(&result.value, &value.value, &d.value, &n.value, nullptr));
        Require(mbedtls_mpi_write_binary(&result.value, block.data(), block.size()));
        return true;
    }
    if (!key->e) {
        if (!key->p || !key->q || !key->d) return Error(140), false;
        Number a, b, product;
        Require(mbedtls_mpi_sub_int(&a.value, &p.value, 1));
        Require(mbedtls_mpi_sub_int(&b.value, &q.value, 1));
        Require(mbedtls_mpi_mul_mpi(&product.value, &a.value, &b.value));
        Require(mbedtls_mpi_inv_mod(&e.value, &d.value, &product.value));
    }
    if (!key->p && !key->q && key->d) {
        Number factorExponent;
        Require(mbedtls_mpi_mul_mpi(&factorExponent.value, &d.value, &e.value));
        Require(mbedtls_mpi_sub_int(&factorExponent.value, &factorExponent.value, 1));
        Require(mbedtls_mpi_shift_r(&factorExponent.value, mbedtls_mpi_lsb(&factorExponent.value)));
        if (mbedtls_mpi_bitlen(&factorExponent.value) > MBEDTLS_MPI_MAX_BITS) throw std::runtime_error("RSA: prime reconstruction exponent exceeds the bundled mbedtls limit");
    }
    Context context;
    const int imported = mbedtls_rsa_import(&context.value, &n.value, key->p ? &p.value : nullptr, key->q ? &q.value : nullptr, key->d ? &d.value : nullptr, &e.value);
    if (imported != 0 || mbedtls_rsa_complete(&context.value) != 0) return Error(3), false;
    Buffer result(block.size());
    if (mbedtls_rsa_private(&context.value, (key->flags & NoBlinding) ? nullptr : Random, nullptr, block.data(), result.data()) != 0) return Error(3), false;
    block.swap(result);
    return true;
}

void Complement(std::vector<unsigned char>& block, const RsaKey* key, bool always) {
    Number n(key->n), value, other;
    Require(mbedtls_mpi_read_binary(&value.value, block.data(), block.size()));
    Require(mbedtls_mpi_sub_mpi(&other.value, &n.value, &value.value));
    if (always || mbedtls_mpi_cmp_mpi(&value.value, &other.value) > 0) Require(mbedtls_mpi_write_binary(&other.value, block.data(), block.size()));
}

int Operation(int length, const unsigned char* input, unsigned char* output, RsaKey* key, int padding, bool privateKey, bool encrypt) try {
    if (const auto custom = Custom(key, privateKey, encrypt)) return custom(length, input, output, key, padding);
    if (!output || (!input && length > 0)) throw std::invalid_argument("RSA: null input or output");
    const auto size = Size(key);
    if (!size || size > static_cast<std::size_t>(std::numeric_limits<int>::max())) return Error(105);
    if (!privateKey) {
        Number n(key->n), e(key->e);
        if (mbedtls_mpi_bitlen(&n.value) > 16384) return Error(105);
        if (mbedtls_mpi_cmp_mpi(&n.value, &e.value) <= 0 || (mbedtls_mpi_bitlen(&n.value) > 3072 && mbedtls_mpi_bitlen(&e.value) > 64)) return Error(101);
    }
    Buffer block(size);
    if (encrypt) {
        if (!Encode(block, input, length, padding, privateKey)) return -1;
    } else {
        if (length < 0 || static_cast<std::size_t>(length) > size) return Error(108);
        if (length) std::memcpy(block.data() + size - length, input, length);
    }
    if (!Transform(block, key, privateKey)) return -1;
    if (padding == X931) {
        if (encrypt && privateKey) Complement(block, key, false);
        if (!encrypt && !privateKey && (block.back() & 15) != 12) Complement(block, key, true);
    }
    if (!encrypt && padding != Pkcs1 && padding != NoPadding && !(privateKey && (padding == Oaep || padding == Sslv23)) && !(!privateKey && padding == X931)) return Error(118);
    const int first = encrypt ? 0 : Decode(block, padding, privateKey);
    if (first < 0) return Error(114);
    const int count = static_cast<int>(block.size()) - first;
    if (count) std::memcpy(output, block.data() + first, count);
    return count;
} catch (const ArithmeticError&) {
    return Error(3);
}

void ClearNumber(RsaNumber* number) {
    if (!number) return;
    if (number->words && !(number->flags & 2)) {
        auto* bytes = reinterpret_cast<volatile unsigned char*>(number->words);
        for (std::size_t index = 0; index < static_cast<std::size_t>(number->capacity) * 8; ++index) bytes[index] = 0;
        free_nid_postfix(number->words);
    }
    const bool allocated = (number->flags & 1) != 0;
    auto* bytes = reinterpret_cast<volatile unsigned char*>(number);
    for (std::size_t index = 0; index < sizeof(RsaNumber); ++index) bytes[index] = 0;
    if (allocated) free_nid_postfix(number);
}

}

extern "C" {

RsaKey* APS5_VABI RSA_new_nid_postfix() {
    auto* key = static_cast<RsaKey*>(calloc_nid_postfix(1, sizeof(RsaKey)));
    if (!key) {
        Error(65);
        return nullptr;
    }
    key->method = &defaultMethod;
    key->references = 1;
    key->flags = 6;
    return key;
}

void APS5_VABI RSA_free_nid_postfix(RsaKey* key) {
    if (!key) return;
    if (key->engine || key->extraData.stack || key->modulusCache || key->primeCache || key->secondPrimeCache || key->blinding || key->threadBlinding) {
        throw std::invalid_argument("RSA_free: externally supplied engine, extra data or cache");
    }
    if (std::atomic_ref(key->references).fetch_sub(1, std::memory_order_acq_rel) > 1) return;
    if (key->method && key->method->finish) key->method->finish(key);
    for (auto* number : {key->n, key->e, key->d, key->p, key->q, key->dp, key->dq, key->inverseQ}) ClearNumber(number);
    free_nid_postfix(key);
}

int APS5_VABI RSA_public_encrypt_nid_postfix(int length, const unsigned char* input, unsigned char* output, RsaKey* key, int padding) {
    return Operation(length, input, output, key, padding, false, true);
}

int APS5_VABI RSA_public_decrypt_nid_postfix(int length, const unsigned char* input, unsigned char* output, RsaKey* key, int padding) {
    return Operation(length, input, output, key, padding, false, false);
}

int APS5_VABI RSA_private_encrypt_nid_postfix(int length, const unsigned char* input, unsigned char* output, RsaKey* key, int padding) {
    return Operation(length, input, output, key, padding, true, true);
}

int APS5_VABI RSA_private_decrypt_nid_postfix(int length, const unsigned char* input, unsigned char* output, RsaKey* key, int padding) {
    return Operation(length, input, output, key, padding, true, false);
}

int LibreSslRsaRetain_nid_no_patch(RsaKey* key) {
    if (!key) throw std::invalid_argument("RSA_up_ref: null key");
    return std::atomic_ref(key->references).fetch_add(1, std::memory_order_relaxed) > 0 ? 1 : 0;
}

int LibreSslRsaCheck_nid_no_patch(const RsaKey* key) try {
    if (!key) throw std::invalid_argument("RSA_check_key: null key");
    if (!key->n || !key->e || !key->d || !key->p || !key->q) return Error(147), 0;
    Number n(key->n), e(key->e), d(key->d), p(key->p), q(key->q), a, b, product, gcd, lcm, check;
    int valid = 1;
    const auto failure = [&](int reason) { Error(reason); valid = 0; };
    if (mbedtls_mpi_is_prime_ext(&p.value, 40, Random, nullptr) != 0) failure(128);
    if (mbedtls_mpi_is_prime_ext(&q.value, 40, Random, nullptr) != 0) failure(129);
    Require(mbedtls_mpi_mul_mpi(&product.value, &p.value, &q.value));
    if (mbedtls_mpi_cmp_mpi(&product.value, &n.value) != 0) failure(127);
    Require(mbedtls_mpi_sub_int(&a.value, &p.value, 1));
    Require(mbedtls_mpi_sub_int(&b.value, &q.value, 1));
    Require(mbedtls_mpi_gcd(&gcd.value, &a.value, &b.value));
    Require(mbedtls_mpi_mul_mpi(&product.value, &a.value, &b.value));
    Require(mbedtls_mpi_div_mpi(&lcm.value, nullptr, &product.value, &gcd.value));
    Require(mbedtls_mpi_mul_mpi(&product.value, &d.value, &e.value));
    Require(mbedtls_mpi_mod_mpi(&check.value, &product.value, &lcm.value));
    if (mbedtls_mpi_cmp_int(&check.value, 1) != 0) failure(123);
    if (key->dp && key->dq && key->inverseQ) {
        Number dp(key->dp), dq(key->dq), inverse(key->inverseQ);
        Require(mbedtls_mpi_mod_mpi(&check.value, &d.value, &a.value));
        if (mbedtls_mpi_cmp_mpi(&check.value, &dp.value) != 0) failure(124);
        Require(mbedtls_mpi_mod_mpi(&check.value, &d.value, &b.value));
        if (mbedtls_mpi_cmp_mpi(&check.value, &dq.value) != 0) failure(125);
        Require(mbedtls_mpi_inv_mod(&check.value, &q.value, &p.value));
        if (mbedtls_mpi_cmp_mpi(&check.value, &inverse.value) != 0) failure(126);
    }
    return valid;
} catch (const ArithmeticError&) {
    return Error(3);
}

}
