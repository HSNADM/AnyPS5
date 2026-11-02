#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <source_location>
#include <stdexcept>

namespace {

void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "TLS protocol check failed at line %u\n", location.line());
    std::abort();
}

int allocationMode = 0;
unsigned allocations = 0;
unsigned releases = 0;
void* live = nullptr;
std::size_t liveSize = 0;

void* APS5_VABI Allocate_nid_no_patch(std::size_t size) {
    ++allocations;
    if (allocationMode == 1) return nullptr;
    if (allocationMode == 2) throw std::bad_alloc();
    Check(!live);
    auto* bytes = static_cast<unsigned char*>(std::malloc(size + 2));
    Check(bytes != nullptr);
    bytes[0] = bytes[size + 1] = 0xA5;
    live = bytes + 1;
    liveSize = size;
    return live;
}

void APS5_VABI Release_nid_no_patch(void* pointer) {
    Check(pointer && pointer == live);
    auto* bytes = static_cast<unsigned char*>(pointer);
    Check(bytes[-1] == 0xA5 && bytes[liveSize] == 0xA5);
    std::free(bytes - 1);
    live = nullptr;
    ++releases;
}

void* APS5_VABI UnexpectedCalloc_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected calloc"); }
void* APS5_VABI UnexpectedRealloc_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

template<class F>
void RejectsOutput(F action) {
    bool threw = false;
    try { action(); } catch (const std::invalid_argument&) { threw = true; }
    Check(threw && !live);
}

void Vectors() {
    struct Vector { const char* input; int status; std::uint32_t mask; };
    constexpr std::array vectors{
        Vector{nullptr, 0, 0x18}, Vector{"all", 0, 0x18}, Vector{"legacy", 0, 0x18},
        Vector{"default", 0, 0x18}, Vector{"secure", 0, 0x18}, Vector{"tlsv1", 0, 0x18},
        Vector{"tlsv1.0", 0, 2}, Vector{"tlsv1.1", 0, 4}, Vector{"tlsv1.2", 0, 8}, Vector{"tlsv1.3", 0, 16},
        Vector{" \tTlSv1.0:\tTLSv1.1,tLsV1.2:TLSV1.3", 0, 0x1E},
        Vector{"all,!tlsv1.2", 0, 16}, Vector{"!tlsv1.3", 0, 8}, Vector{"!all", 0, 0},
        Vector{"all,!all,!tlsv1.2", 0, 16}, Vector{"tlsv1.0,!tlsv1.0,!tlsv1.3", 0, 8},
        Vector{"!all,!all", 0, 0}, Vector{"!all,tlsv1.1", 0, 4}, Vector{"tlsv1.2,tlsv1.2", 0, 8},
        Vector{"tlsv1.0,!legacy", 0, 2}, Vector{"tlsv1.0,!tlsv1", 0, 2}, Vector{"!tlsv1.0", 0, 0x18},
        Vector{"", -1, 0}, Vector{" ", -1, 0}, Vector{"\t", -1, 0}, Vector{"!", -1, 0},
        Vector{"all,", -1, 0}, Vector{",all", -1, 0}, Vector{"all::secure", -1, 0},
        Vector{"tlsv1.2 ", -1, 0}, Vector{"! tlsv1.2", -1, 0}, Vector{"all\n", -1, 0},
        Vector{"\nall", -1, 0}, Vector{"\rall", -1, 0}, Vector{"tlsv1.4", -1, 0},
        Vector{"tlsv1.2\x80", -1, 0}, Vector{"all,!bogus", -1, 0}, Vector{"!!all", -1, 0},
        Vector{"TLS1.2", -1, 0}, Vector{"tlsv1.2\0ignored", 0, 8}
    };
    for (const auto& vector : vectors) {
        struct Guarded { std::uint32_t before; std::uint32_t mask; std::uint32_t after; } output{0x12345678, 0xDEADBEEF, 0x87654321};
        const auto allocatedBefore = allocations;
        const auto releasedBefore = releases;
        std::array<char, 128> text{};
        if (vector.input) std::strcpy(text.data(), vector.input);
        const auto snapshot = text;
        Check(tls_config_parse_protocols_nid_postfix(&output.mask, vector.input ? text.data() : nullptr) == vector.status);
        Check(output.mask == (vector.status ? 0xDEADBEEF : vector.mask));
        Check(output.before == 0x12345678 && output.after == 0x87654321 && text == snapshot && !live);
        Check(allocations - allocatedBefore == static_cast<unsigned>(vector.input != nullptr));
        Check(releases - releasedBefore == static_cast<unsigned>(vector.input != nullptr));
        if (vector.input) Check(liveSize == std::strlen(vector.input) + 1);
    }
}

void FailuresAndAliasing() {
    for (int mode : {1, 2}) {
        allocationMode = mode;
        std::uint32_t output = 0xABCDEF12;
        const auto releasedBefore = releases;
        Check(tls_config_parse_protocols_nid_postfix(&output, "all") == -1 && output == 0xABCDEF12 && !live);
        Check(tls_config_parse_protocols_nid_postfix(nullptr, "all") == -1 && !live);
        Check(tls_config_parse_protocols_nid_postfix(&output, nullptr) == 0 && output == 0x18);
        Check(releases == releasedBefore);
    }
    allocationMode = 0;
    Check(tls_config_parse_protocols_nid_postfix(nullptr, "bogus") == -1 && !live);
    RejectsOutput([] { tls_config_parse_protocols_nid_postfix(nullptr, nullptr); });
    RejectsOutput([] { tls_config_parse_protocols_nid_postfix(nullptr, "all"); });
    struct Aliased { std::uint32_t mask; std::array<char, 32> tail; } alias{};
    auto* text = reinterpret_cast<char*>(&alias);
    std::strcpy(text, "tlsv1.2,tlsv1.3");
    const auto before = alias.tail;
    Check(tls_config_parse_protocols_nid_postfix(&alias.mask, text) == 0 && alias.mask == 0x18);
    Check(alias.tail == before && !live);
}

} // namespace

int main() {
    const std::array<void*, 10> api{
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Release_nid_no_patch), reinterpret_cast<void*>(UnexpectedCalloc_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedRealloc_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    Vectors();
    FailuresAndAliasing();
    std::puts("TLS protocol masks, token grammar, allocation failures, output ownership and aliasing checks passed");
}
