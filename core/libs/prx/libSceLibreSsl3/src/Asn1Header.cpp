#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include <bit>
#include <limits>
#include <optional>
#include <stdexcept>

namespace {

struct Reader {
    const unsigned char* pointer;
    std::uint64_t remaining;

    bool Next(unsigned char& byte) {
        if (!remaining) return false;
        if (!pointer) throw std::invalid_argument("ASN1_get_object: null input bytes");
        byte = *pointer++;
        --remaining;
        return true;
    }
};

struct Header {
    std::uint64_t length = 0;
    std::uint32_t tag = 0;
    int tagClass = 0;
    bool constructed = false;
    bool indefinite = false;
};

std::optional<Header> Parse(Reader& reader) {
    unsigned char byte;
    if (!reader.Next(byte)) return std::nullopt;
    Header header;
    header.tagClass = byte & 0xC0;
    header.constructed = (byte & 0x20) != 0;
    header.tag = byte & 0x1F;
    if (header.tag == 0x1F) {
        header.tag = 0;
        do {
            if (!reader.Next(byte) || header.tag > (std::numeric_limits<std::uint32_t>::max() >> 7)) return std::nullopt;
            header.tag = (header.tag << 7) | (byte & 0x7F);
        } while (byte & 0x80);
    }
    if (!reader.Next(byte)) return std::nullopt;
    if (byte < 0x80) {
        header.length = byte;
    } else if (byte == 0x80) {
        if (!header.constructed) return std::nullopt;
        header.indefinite = true;
    } else {
        const int count = byte & 0x7F;
        if (count == 0x7F) return std::nullopt;
        for (int index = 0; index < count; ++index) {
            if (!reader.Next(byte) || header.length > (std::numeric_limits<std::uint64_t>::max() >> 8)) return std::nullopt;
            header.length = (header.length << 8) | byte;
        }
    }
    return header;
}

} // namespace

extern "C" {

int APS5_VABI ASN1_get_object_nid_postfix(const unsigned char** input, std::int64_t* length, int* tag, int* tagClass, std::int64_t available) {
    if (!input || !length || !tag || !tagClass) throw std::invalid_argument("ASN1_get_object: null argument");
    *tagClass = 0;
    *tag = 0;
    *length = 0;
    Reader reader{*input, static_cast<std::uint64_t>(available)};
    const auto header = Parse(reader);
    if (!header || header->tag > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
        LibreSslPutError_nid_no_patch(13, 0xfff, 123);
        return 0x80;
    }
    int result = 0;
    if (header->length > reader.remaining || header->length > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        LibreSslPutError_nid_no_patch(13, 0xfff, 155);
        result = 0x80;
    }
    *tagClass = header->tagClass;
    *tag = static_cast<int>(header->tag);
    *length = std::bit_cast<std::int64_t>(header->length);
    *input = reader.pointer;
    return result | (header->constructed ? 0x20 : 0) | (header->indefinite ? 1 : 0);
}

}
