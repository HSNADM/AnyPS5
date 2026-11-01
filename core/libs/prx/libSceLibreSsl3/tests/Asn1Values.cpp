#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace {

void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "ASN.1 value check failed at line %u\n", location.line());
    std::abort();
}

template<class Exception, class F>
void Throws(F action) {
    bool threw = false;
    try { action(); } catch (const Exception&) { threw = true; }
    Check(threw);
}

void Comparisons() {
    unsigned char firstBytes[]{0, 0x80, 0xFE, 3};
    unsigned char secondBytes[]{0, 0x80, 0xFF, 2};
    Asn1String first{4, 4, firstBytes, 0x123456};
    Asn1String second{4, 4, secondBytes, -1};
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(nullptr, nullptr) == -1);
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, nullptr) == -1);
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(nullptr, &second) == -1);
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) < 0);
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&second, &first) > 0);
    second.data = firstBytes;
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) == 0);
    second.type = 19;
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) == -15);
    first.length = 1;
    first.data = nullptr;
    second.length = 3;
    second.data = nullptr;
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) == -2);
    first.length = second.length = 0;
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) == -15);
    first.type = second.type;
    Check(ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second) == 0);
    first.length = second.length = 3;
    Throws<std::invalid_argument>([&] { ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second); });
    first.length = second.length = -3;
    Throws<std::invalid_argument>([&] { ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second); });
    first.length = std::numeric_limits<int>::max();
    second.length = -1;
    Throws<std::overflow_error>([&] { ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second); });
    first.length = second.length = 0;
    first.type = std::numeric_limits<int>::min();
    second.type = 1;
    Throws<std::overflow_error>([&] { ASN1_OCTET_STRING_cmp_nid_postfix(&first, &second); });
    Check(std::equal(std::begin(firstBytes), std::end(firstBytes), std::array<unsigned char, 4>{0, 0x80, 0xFE, 3}.begin()));
    Check(std::equal(std::begin(secondBytes), std::end(secondBytes), std::array<unsigned char, 4>{0, 0x80, 0xFF, 2}.begin()));
}

std::unordered_map<void*, std::size_t> allocations;
void* clearOnFree = nullptr;
std::size_t clearLength = 0;
bool failAllocation = false;

void* APS5_VABI Allocate_nid_no_patch(std::size_t size) {
    if (failAllocation) return nullptr;
    auto* memory = static_cast<unsigned char*>(std::malloc(size + 32));
    Check(memory != nullptr);
    std::memset(memory, 0xA5, size + 32);
    auto* result = memory + 16;
    allocations.emplace(result, size);
    return result;
}

void APS5_VABI Release_nid_no_patch(void* pointer) {
    if (!pointer) return;
    const auto found = allocations.find(pointer);
    Check(found != allocations.end());
    auto* bytes = static_cast<unsigned char*>(pointer);
    const auto* memory = bytes - 16;
    for (std::size_t index = 0; index < 16; ++index) Check(memory[index] == 0xA5 && bytes[found->second + index] == 0xA5);
    if (pointer == clearOnFree) {
        Check(clearLength <= found->second);
        Check(std::all_of(bytes, bytes + clearLength, [](unsigned char byte) { return byte == 0; }));
        clearOnFree = nullptr;
    }
    allocations.erase(found);
    std::free(bytes - 16);
}

void* APS5_VABI UnexpectedCalloc_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected calloc"); }
void* APS5_VABI UnexpectedReallocate_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void Integers() {
    std::array<void*, 10> api{
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Release_nid_no_patch), reinterpret_cast<void*>(UnexpectedCalloc_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    struct Vector { std::int64_t number; std::vector<unsigned char> magnitude; };
    const std::array<Vector, 15> vectors{{
        {0, {0}}, {1, {1}}, {-1, {1}}, {127, {0x7F}}, {-128, {0x80}}, {128, {0x80}},
        {255, {0xFF}}, {-255, {0xFF}}, {256, {1, 0}}, {-256, {1, 0}}, {65535, {0xFF, 0xFF}},
        {-65536, {1, 0, 0}}, {0x123456789ABCDE, {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE}},
        {std::numeric_limits<std::int64_t>::min(), {0x80, 0, 0, 0, 0, 0, 0, 0}},
        {std::numeric_limits<std::int64_t>::max(), {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}
    }};
    struct Guarded { std::array<unsigned char, 16> left; Asn1String value; std::array<unsigned char, 16> right; } guarded{};
    guarded.left.fill(0xC3);
    guarded.right.fill(0x3C);
    auto& value = guarded.value;
    for (const auto& vector : vectors) {
        clearOnFree = value.data;
        clearLength = static_cast<std::size_t>(value.length);
        value.flags = -1;
        value.type = 27;
        Check(ASN1_INTEGER_set_nid_postfix(&value, vector.number) == 1);
        Check(clearOnFree == nullptr && allocations.size() == 1);
        Check(value.length == static_cast<int>(vector.magnitude.size()) && value.type == (vector.number < 0 ? 0x102 : 2) && value.flags == 0);
        Check(value.data && allocations.at(value.data) >= vector.magnitude.size());
        Check(std::equal(vector.magnitude.begin(), vector.magnitude.end(), value.data));
    }
    clearOnFree = value.data;
    clearLength = static_cast<std::size_t>(value.length);
    failAllocation = true;
    Check(ASN1_INTEGER_set_nid_postfix(&value, -3) == 0);
    Check(value.length == 0 && value.type == 0x102 && value.flags == 0 && !value.data && allocations.empty() && !clearOnFree);
    failAllocation = false;
    value.length = -17;
    value.data = nullptr;
    Check(ASN1_INTEGER_set_nid_postfix(&value, 0) == 1 && value.length == 1 && value.data[0] == 0);
    value.length = -1;
    const auto before = value;
    Throws<std::invalid_argument>([&] { ASN1_INTEGER_set_nid_postfix(&value, 1); });
    Check(std::memcmp(&before, &value, sizeof(value)) == 0 && allocations.size() == 1);
    value.length = 1;
    free_nid_postfix(value.data);
    Check(allocations.empty());
    Throws<std::invalid_argument>([] { ASN1_INTEGER_set_nid_postfix(nullptr, 0); });
    for (auto byte : guarded.left) Check(byte == 0xC3);
    for (auto byte : guarded.right) Check(byte == 0x3C);
}

} // namespace

int main() {
    Comparisons();
    Integers();
    std::puts("ASN.1 comparison, signed integer, ownership, clearing and allocation-failure checks passed");
}
