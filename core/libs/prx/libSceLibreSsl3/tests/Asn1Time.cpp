#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "ASN.1 time check failed at line %u\n", location.line());
    std::abort();
}

Asn1String Time(std::string_view bytes, int type = -1) {
    return {static_cast<int>(bytes.size()), type, reinterpret_cast<unsigned char*>(const_cast<char*>(bytes.data())), -1};
}

alignas(Asn1String) std::array<unsigned char, sizeof(Asn1String) + 32> storage{};
bool allocated = false;
bool failAllocation = false;
std::size_t attempts = 0;
std::size_t frees = 0;

void* APS5_VABI AllocateZeroed_nid_no_patch(std::size_t count, std::size_t size) {
    Check(count == 1 && size == sizeof(Asn1String) && !allocated);
    ++attempts;
    if (failAllocation) return nullptr;
    storage.fill(0xA5);
    auto* result = storage.data() + 16;
    std::memset(result, 0, size);
    allocated = true;
    return result;
}

void APS5_VABI Release_nid_no_patch(void* pointer) {
    if (!pointer) return;
    Check(allocated && pointer == storage.data() + 16);
    for (std::size_t index = 0; index < 16; ++index) Check(storage[index] == 0xA5 && storage[storage.size() - 16 + index] == 0xA5);
    allocated = false;
    ++frees;
}

void* APS5_VABI UnexpectedAllocate_nid_no_patch(std::size_t) { throw std::runtime_error("unexpected malloc"); }
void* APS5_VABI UnexpectedReallocate_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void Constructor() {
    std::array<void*, 10> api{
        reinterpret_cast<void*>(UnexpectedAllocate_nid_no_patch), reinterpret_cast<void*>(Release_nid_no_patch), reinterpret_cast<void*>(AllocateZeroed_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    ERR_clear_error_nid_postfix();
    for (int iteration = 0; iteration < 3; ++iteration) {
        auto* value = ASN1_TIME_new_nid_postfix();
        Check(value && allocated && reinterpret_cast<unsigned char*>(value) == storage.data() + 16);
        const Asn1String expected{0, -1, nullptr, 0x40};
        Check(std::memcmp(value, &expected, sizeof(expected)) == 0 && ERR_get_error_nid_postfix() == 0);
        free_nid_postfix(value);
    }
    Check(attempts == 3 && frees == 3 && !allocated);
    failAllocation = true;
    Check(ASN1_TIME_new_nid_postfix() == nullptr && !allocated && attempts == 4 && frees == 3);
    Check(ERR_get_error_nid_postfix() == 0x0DFFF041);
    Check(ERR_get_error_nid_postfix() == 0x0DFFF041 && ERR_get_error_nid_postfix() == 0);
    failAllocation = false;
}

void Difference(std::string_view fromText, std::string_view toText, int expectedDays, int expectedSeconds) {
    auto from = Time(fromText, std::numeric_limits<int>::max());
    auto to = Time(toText, 0);
    const auto fromBefore = from;
    const auto toBefore = to;
    int days = 91;
    int seconds = 93;
    Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &from, &to) == 1 && days == expectedDays && seconds == expectedSeconds);
    Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &to, &from) == 1 && days == -expectedDays && seconds == -expectedSeconds);
    int alias = 71;
    Check(ASN1_TIME_diff_nid_postfix(&alias, &alias, &from, &to) == 1 && alias == expectedDays);
    Check(std::memcmp(&from, &fromBefore, sizeof(from)) == 0 && std::memcmp(&to, &toBefore, sizeof(to)) == 0);
}

void Differences() {
    Difference("500101000000Z", "19500101000000Z", 0, 0);
    Difference("491231235959Z", "20500101000000Z", 0, 1);
    Difference("00000228000000Z", "00000301000000Z", 2, 0);
    Difference("19000228000000Z", "19000301000000Z", 1, 0);
    Difference("20000228235959Z", "20000301000001Z", 1, 2);
    Difference("21000228000000Z", "21000301000000Z", 1, 0);
    Difference("20240228235959Z", "20240301000000Z", 1, 1);
    Difference("20240102235959Z", "20240102000000Z", 0, -86399);
    Difference("20240103000000Z", "20240101235959Z", -1, -1);
    Difference("00000101000000Z", "04000101000000Z", 146097, 0);
    Difference("00000101000000Z", "99991231235959Z", 3652424, 86399);
    auto from = Time("240101000000Z");
    auto to = Time("240103000003Z");
    Check(ASN1_TIME_diff_nid_postfix(&from.length, &to.type, &from, &to) == 1 && from.length == 2 && to.type == 3);
}

constexpr std::array<std::string_view, 17> Invalid{
    "", "20230229000000Z", "20000230000000Z", "20241301000000Z", "20240001000000Z", "20240100000000Z",
    "20240431000000Z", "20240101240000Z", "20240101006000Z", "20240101000060Z", "20240101000000z",
    "20240101000000+", "2024010100000AZ", "2401010000Z", "20240101000000.0Z", "240101000000+0000", "not-a-date-here"
};

void Rejections() {
    auto valid = Time("240101000000Z", 23);
    for (auto text : Invalid) {
        auto invalid = Time(text);
        int days = 91;
        int seconds = 93;
        Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &invalid, &valid) == 0 && days == 91 && seconds == 93);
        Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &valid, &invalid) == 0 && days == 91 && seconds == 93);
        Check(ASN1_TIME_diff_nid_postfix(nullptr, nullptr, &invalid, nullptr) == 0);
        Check(X509_cmp_current_time_nid_postfix(&invalid) == 0);
    }
    for (int length : {-1, 0, 13, 15, std::numeric_limits<int>::max()}) {
        Asn1String invalid{length, 23, nullptr, 0};
        int days = 91;
        int seconds = 93;
        Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &invalid, &valid) == 0 && days == 91 && seconds == 93);
        Check(X509_cmp_current_time_nid_postfix(&invalid) == 0);
    }
    for (int selection = 0; selection < 3; ++selection) {
        int output = 93;
        bool threw = false;
        try {
            ASN1_TIME_diff_nid_postfix(selection == 0 ? &output : nullptr, selection == 1 ? &output : nullptr, &valid, &valid);
        } catch (const std::invalid_argument&) { threw = true; }
        Check(threw && output == 93);
    }
    Check(X509_cmp_current_time_nid_postfix(nullptr) == 0 && ERR_get_error_nid_postfix() == 0);
}

std::string Encode(std::int64_t epoch, int& type) {
    const auto native = static_cast<std::time_t>(epoch);
    const auto* broken = std::gmtime(&native);
    Check(broken != nullptr);
    const int year = broken->tm_year + 1900;
    type = year >= 1950 && year < 2050 ? 23 : 24;
    char bytes[32]{};
    const int count = type == 23 ? std::snprintf(bytes, sizeof(bytes), "%02d%02d%02d%02d%02d%02dZ", year % 100,
        broken->tm_mon + 1, broken->tm_mday, broken->tm_hour, broken->tm_min, broken->tm_sec) :
        std::snprintf(bytes, sizeof(bytes), "%04d%02d%02d%02d%02d%02dZ", year,
        broken->tm_mon + 1, broken->tm_mday, broken->tm_hour, broken->tm_min, broken->tm_sec);
    Check(count == (type == 23 ? 13 : 15));
    return bytes;
}

void Clock() {
    const auto captured = time_nid_postfix(nullptr);
    int type = 0;
    const auto currentBytes = Encode(captured, type);
    auto current = Time(currentBytes, type);
    Check(X509_cmp_current_time_nid_postfix(&current) == -1);
    current.type = 0;
    Check(X509_cmp_current_time_nid_postfix(&current) == -1);
    current.type = -1;
    Check(X509_cmp_current_time_nid_postfix(&current) == 0);
    const auto pastBytes = Encode(captured - 86400, type);
    auto past = Time(pastBytes, type);
    Check(X509_cmp_current_time_nid_postfix(&past) == -1);
    const auto futureBytes = Encode(captured + 86400, type);
    auto future = Time(futureBytes, type);
    Check(X509_cmp_current_time_nid_postfix(&future) == 1);
    auto wrongProfile = Time("20491231235959Z", 24);
    Check(X509_cmp_current_time_nid_postfix(&wrongProfile) == 0);
    auto correctProfile = Time("20500101000000Z", 24);
    Check(X509_cmp_current_time_nid_postfix(&correctProfile) != 0);
    current.type = 23;
    int days = 0;
    int seconds = 0;
    const auto before = time_nid_postfix(nullptr);
    Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, &current, nullptr) == 1);
    const auto after = time_nid_postfix(nullptr);
    const auto difference = static_cast<std::int64_t>(days) * 86400 + seconds;
    Check(difference >= before - captured && difference <= after - captured);
    const auto reverseBefore = time_nid_postfix(nullptr);
    Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, nullptr, &current) == 1);
    const auto reverseAfter = time_nid_postfix(nullptr);
    const auto reverse = static_cast<std::int64_t>(days) * 86400 + seconds;
    Check(reverse >= captured - reverseAfter && reverse <= captured - reverseBefore);
    const auto bothBefore = time_nid_postfix(nullptr);
    Check(ASN1_TIME_diff_nid_postfix(&days, &seconds, nullptr, nullptr) == 1);
    const auto bothAfter = time_nid_postfix(nullptr);
    const auto both = static_cast<std::int64_t>(days) * 86400 + seconds;
    Check(both >= bothBefore - bothAfter && both <= bothAfter - bothBefore);
}

} // namespace

int main() {
    Constructor();
    Differences();
    Rejections();
    Clock();
    std::puts("ASN.1 time construction, calendar bounds, parsing, output ordering and certificate profile checks passed");
}
