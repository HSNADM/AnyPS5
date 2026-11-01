#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <vector>

namespace {

void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "ASN.1 header check failed at line %u\n", location.line());
    std::abort();
}

void Case(const std::vector<unsigned char>& bytes, std::int64_t available, int expectedResult, std::int64_t expectedLength,
          int expectedTag, int expectedClass, std::size_t consumed, int reason = 0) {
    const auto original = bytes;
    const auto* cursor = bytes.data();
    struct Outputs { std::uint64_t left; int tag; int tagClass; std::int64_t length; std::uint64_t right; } outputs{0x123456789ABCDEF0, 71, 73, 79, 0xFEDCBA9876543210};
    ERR_clear_error_nid_postfix();
    const int result = ASN1_get_object_nid_postfix(&cursor, &outputs.length, &outputs.tag, &outputs.tagClass, available);
    Check(result == expectedResult && outputs.length == expectedLength && outputs.tag == expectedTag && outputs.tagClass == expectedClass);
    Check(cursor == (consumed ? bytes.data() + consumed : bytes.data()));
    Check(outputs.left == 0x123456789ABCDEF0 && outputs.right == 0xFEDCBA9876543210 && bytes == original);
    const auto expectedError = reason ? std::uint64_t{0x0DFFF000} | static_cast<unsigned int>(reason) : 0;
    Check(ERR_get_error_nid_postfix() == expectedError && ERR_get_error_nid_postfix() == 0);
}

void Headers() {
    for (int tagClass : {0, 0x40, 0x80, 0xC0}) {
        for (int constructed : {0, 0x20}) {
            Case({static_cast<unsigned char>(tagClass | constructed | 5), 0}, 2, constructed, 0, 5, tagClass, 2);
        }
    }
    Case({0, 0}, 2, 0, 0, 0, 0, 2);
    Case({4, 3, 0x41, 0, 0xFF}, 5, 0, 3, 4, 0, 2);
    Case({4, 0x81, 3, 1, 2, 3}, 6, 0, 3, 4, 0, 3);
    Case({4, 0x82, 0, 1, 0xAA}, 5, 0, 1, 4, 0, 4);
    Case({0x1F, 0x1F, 0}, 3, 0, 0, 31, 0, 3);
    Case({0x9F, 0x81, 0, 0}, 4, 0, 0, 128, 0x80, 4);
    Case({0xFF, 0x80, 0x80, 0x1E, 0}, 5, 0x20, 0, 30, 0xC0, 5);
    Case({0x1F, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0}, 7, 0, 0, std::numeric_limits<int>::max(), 0, 7);
    Case({0x30, 0x80}, 2, 0x21, 0, 16, 0, 2);
    Case({0x30, 3, 1}, 3, 0xA0, 3, 16, 0, 2, 155);
    Case({4, 3, 1}, 3, 0x80, 3, 4, 0, 2, 155);
    Case({4, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA}, 12, 0, 1, 4, 0, 11);
    std::vector<unsigned char> padded(128, 0);
    padded[0] = 4;
    padded[1] = 0xFE;
    Case(padded, 128, 0, 0, 4, 0, 128);
    padded.back() = 1;
    padded.push_back(0xAA);
    Case(padded, 129, 0, 1, 4, 0, 128);
}

void Failures() {
    for (const auto& bytes : std::vector<std::vector<unsigned char>>{
        {}, {4}, {0x1F}, {0x1F, 0x80}, {4, 0xFF}, {4, 0x82, 1}, {4, 0x80},
        {0x1F, 0x88, 0x80, 0x80, 0x80, 0, 0}, {0x1F, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F, 0},
        {0x1F, 0x90, 0x80, 0x80, 0x80, 0, 0}, {4, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0}}) {
        Case(bytes, static_cast<std::int64_t>(bytes.size()), 0x80, 0, 0, 0, 0, 123);
    }
    const std::vector<unsigned char> longHeader{4, 0x88, 0, 0, 0, 0, 0, 0, 0, 4};
    for (int available = 0; available < 10; ++available)
        Case(longHeader, available, 0x80, 0, 0, 0, 0, 123);
    Case(longHeader, 10, 0x80, 4, 4, 0, 10, 155);
}

void WideLengths() {
    const auto maximum = std::numeric_limits<std::int64_t>::max();
    Case({4, 1}, -1, 0, 1, 4, 0, 2);
    Case({4, 1}, std::numeric_limits<std::int64_t>::min(), 0, 1, 4, 0, 2);
    Case({4, 1}, maximum, 0, 1, 4, 0, 2);
    Case({4, 0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, maximum, 0x80, maximum, 4, 0, 10, 155);
    Case({4, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0}, maximum, 0x80, std::numeric_limits<std::int64_t>::min(), 4, 0, 10, 155);
    Case({4, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, -1, 0x80, -1, 4, 0, 10, 155);
    Case({4, 0x85, 1, 0, 0, 0, 0}, -1, 0, 0x100000000, 4, 0, 7);
}

void AliasesAndNulls() {
    const std::array<unsigned char, 3> bytes{0x9F, 31, 0};
    const auto* cursor = bytes.data();
    std::int64_t length = 91;
    int alias = 93;
    Check(ASN1_get_object_nid_postfix(&cursor, &length, &alias, &alias, bytes.size()) == 0 && alias == 31 && length == 0 && cursor == bytes.data() + 3);
    for (int selection = 0; selection < 4; ++selection) {
        cursor = bytes.data();
        length = 91;
        int tag = 93;
        int tagClass = 97;
        bool threw = false;
        try {
            ASN1_get_object_nid_postfix(selection == 0 ? nullptr : &cursor, selection == 1 ? nullptr : &length,
                selection == 2 ? nullptr : &tag, selection == 3 ? nullptr : &tagClass, bytes.size());
        } catch (const std::invalid_argument&) { threw = true; }
        Check(threw && cursor == bytes.data() && length == 91 && tag == 93 && tagClass == 97);
    }
    cursor = nullptr;
    int tag = 93;
    int tagClass = 97;
    ERR_clear_error_nid_postfix();
    Check(ASN1_get_object_nid_postfix(&cursor, &length, &tag, &tagClass, 0) == 0x80 && !cursor && !length && !tag && !tagClass);
    Check(ERR_get_error_nid_postfix() == 0x0DFFF07B && ERR_get_error_nid_postfix() == 0);
    bool threw = false;
    try { ASN1_get_object_nid_postfix(&cursor, &length, &tag, &tagClass, 1); }
    catch (const std::invalid_argument&) { threw = true; }
    Check(threw && !length && !tag && !tagClass && ERR_get_error_nid_postfix() == 0);
    LibreSslPutError_nid_no_patch(7, 1, 17);
    Check(ASN1_get_object_nid_postfix(&cursor, &length, &tag, &tagClass, 0) == 0x80);
    Check(ERR_get_error_nid_postfix() == 0x07001011 && ERR_get_error_nid_postfix() == 0x0DFFF07B && ERR_get_error_nid_postfix() == 0);
}

} // namespace

int main() {
    Headers();
    Failures();
    WideLengths();
    AliasesAndNulls();
    std::puts("ASN.1 BER header, pointer advancement, 64-bit length, alias and error-order checks passed");
}
