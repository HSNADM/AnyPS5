#pragma once

#include "SceTypes.hpp"

#include <cstddef>
#include <cstdint>

namespace LibreSsl {

struct RsaKey;

struct RsaNumber {
    std::uint64_t* words;
    std::int32_t top;
    std::int32_t capacity;
    std::int32_t negative;
    std::int32_t flags;
};

using RsaOperation = int (APS5_VABI *)(int, const unsigned char*, unsigned char*, RsaKey*, int);

struct RsaMethod {
    const char* name;
    RsaOperation publicEncrypt;
    RsaOperation publicDecrypt;
    RsaOperation privateEncrypt;
    RsaOperation privateDecrypt;
    void* modularExponentiation;
    void* numberExponentiation;
    int (APS5_VABI *initialize)(RsaKey*);
    int (APS5_VABI *finish)(RsaKey*);
    std::int32_t flags;
    void* appData;
    int (APS5_VABI *sign)(int, const unsigned char*, unsigned int, unsigned char*, unsigned int*, const RsaKey*);
    int (APS5_VABI *verify)(int, const unsigned char*, unsigned int, const unsigned char*, unsigned int, const RsaKey*);
    void* generateKey;
};

struct RsaKey {
    std::int32_t pad;
    std::int64_t version;
    const RsaMethod* method;
    void* engine;
    RsaNumber* n;
    RsaNumber* e;
    RsaNumber* d;
    RsaNumber* p;
    RsaNumber* q;
    RsaNumber* dp;
    RsaNumber* dq;
    RsaNumber* inverseQ;
    struct ExtraData {
        void* stack;
        std::int32_t dummy;
    } extraData;
    std::int32_t references;
    std::int32_t flags;
    void* modulusCache;
    void* primeCache;
    void* secondPrimeCache;
    void* blinding;
    void* threadBlinding;
};

static_assert(sizeof(RsaNumber) == 24 && offsetof(RsaNumber, flags) == 20);
static_assert(sizeof(RsaMethod) == 112 && offsetof(RsaMethod, flags) == 72);
static_assert(sizeof(RsaKey) == 160 && offsetof(RsaKey, n) == 32);
static_assert(offsetof(RsaKey, references) == 112 && offsetof(RsaKey, flags) == 116);

}

extern "C" {
int LibreSslRsaCheck_nid_no_patch(const LibreSsl::RsaKey* key);
int LibreSslRsaRetain_nid_no_patch(LibreSsl::RsaKey* key);
}
