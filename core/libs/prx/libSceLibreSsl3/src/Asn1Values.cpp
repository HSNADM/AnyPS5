#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/include/Api.hpp"
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

int Difference(int first, int second) {
    const auto result = static_cast<std::int64_t>(first) - second;
    if (result < std::numeric_limits<int>::min() || result > std::numeric_limits<int>::max())
        throw std::overflow_error("ASN.1 comparison: signed difference overflow");
    return static_cast<int>(result);
}

} // namespace

extern "C" {

int APS5_VABI ASN1_STRING_set_nid_postfix(Asn1String* value, const void* input, int length) {
    if (length == -1) {
        if (!input) return 0;
        const auto measured = std::strlen(static_cast<const char*>(input));
        if (measured > static_cast<std::size_t>(std::numeric_limits<int>::max())) return 0;
        length = static_cast<int>(measured);
    }
    if (!value) throw std::invalid_argument("ASN1_STRING_set: null string");
    if (!(value->flags & 0x10) && value->data) {
        if (value->length < 0) throw std::invalid_argument("ASN1_STRING_set: negative old length");
        const auto source = reinterpret_cast<std::uintptr_t>(input);
        const auto old = reinterpret_cast<std::uintptr_t>(value->data);
        const auto oldSize = static_cast<std::uint64_t>(value->length);
        if (input && length > 0 && length < std::numeric_limits<int>::max() && (source == old || (source > old && source - old < oldSize) ||
            (source < old && old - source < static_cast<std::uint64_t>(length))))
            throw std::invalid_argument("ASN1_STRING_set: input aliases released storage");
        auto* bytes = static_cast<volatile unsigned char*>(value->data);
        for (int index = 0; index < value->length; ++index) bytes[index] = 0;
        free_nid_postfix(value->data);
    }
    value->flags &= ~std::int64_t{0x10};
    value->data = nullptr;
    value->length = 0;
    if (length < 0 || length >= std::numeric_limits<int>::max()) return 0;
    auto* data = static_cast<unsigned char*>(calloc_nid_postfix(1, static_cast<std::size_t>(length) + 1));
    if (!data) {
        LibreSslPutError_nid_no_patch(13, 0xfff, 65);
        return 0;
    }
    if (input) std::memcpy(data, input, static_cast<std::size_t>(length));
    value->data = data;
    value->length = length;
    return 1;
}

int APS5_VABI ASN1_OCTET_STRING_cmp_nid_postfix(const Asn1String* first, const Asn1String* second) {
    if (!first || !second) return -1;
    if (const int difference = Difference(first->length, second->length)) return difference;
    if (first->length != 0) {
        if (first->length < 0 || !first->data || !second->data)
            throw std::invalid_argument("ASN.1 comparison: invalid equal-length buffers");
        if (const int difference = std::memcmp(first->data, second->data, static_cast<std::size_t>(first->length)))
            return difference;
    }
    return Difference(first->type, second->type);
}

int APS5_VABI ASN1_INTEGER_set_nid_postfix(Asn1String* value, std::int64_t number) {
    if (!value) throw std::invalid_argument("ASN1_INTEGER_set: null integer");
    if (value->data) {
        if (value->length < 0) throw std::invalid_argument("ASN1_INTEGER_set: negative old length");
        auto* bytes = static_cast<volatile unsigned char*>(value->data);
        for (int index = 0; index < value->length; ++index) bytes[index] = 0;
        free_nid_postfix(value->data);
    }
    *value = Asn1String{0, number < 0 ? 0x102 : 2, nullptr, 0};
    auto* data = static_cast<unsigned char*>(malloc_nid_postfix(sizeof(std::uint64_t)));
    if (!data) return 0;
    const auto magnitude = number < 0 ? std::uint64_t{0} - static_cast<std::uint64_t>(number) : static_cast<std::uint64_t>(number);
    int length = 1;
    for (auto remaining = magnitude >> 8; remaining != 0; remaining >>= 8) ++length;
    for (int index = 0; index < length; ++index)
        data[index] = static_cast<unsigned char>(magnitude >> (8 * (length - index - 1)));
    value->data = data;
    value->length = length;
    return 1;
}

}
