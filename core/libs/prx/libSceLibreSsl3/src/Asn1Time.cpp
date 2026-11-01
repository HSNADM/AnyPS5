#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/include/Api.hpp"
#include <chrono>
#include <optional>
#include <stdexcept>

namespace {

struct ParsedTime {
    std::int64_t seconds;
    int year;
    int type;
};

constexpr std::int64_t DateSeconds(int year, unsigned int month, unsigned int day) {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::sys_days{std::chrono::year{year} / month / day}.time_since_epoch()).count();
}

std::optional<ParsedTime> Parse(const Asn1String& value) {
    if (!value.data || (value.length != 13 && value.length != 15)) return std::nullopt;
    if (value.data[value.length - 1] != 'Z') return std::nullopt;
    for (int index = 0; index < value.length - 1; ++index)
        if (value.data[index] < '0' || value.data[index] > '9') return std::nullopt;
    const auto pair = [&](int offset) { return (value.data[offset] - '0') * 10 + value.data[offset + 1] - '0'; };
    const bool generalized = value.length == 15;
    const int year = generalized ? pair(0) * 100 + pair(2) : pair(0) + (pair(0) < 50 ? 2000 : 1900);
    const int offset = generalized ? 4 : 2;
    const auto month = static_cast<unsigned int>(pair(offset));
    const auto day = static_cast<unsigned int>(pair(offset + 2));
    const int hour = pair(offset + 4);
    const int minute = pair(offset + 6);
    const int second = pair(offset + 8);
    const std::chrono::year_month_day date{std::chrono::year{year}, std::chrono::month{month}, std::chrono::day{day}};
    if (!date.ok() || hour > 23 || minute > 59 || second > 59) return std::nullopt;
    return ParsedTime{DateSeconds(year, month, day) + hour * 3600 + minute * 60 + second, year, generalized ? 24 : 23};
}

std::optional<std::int64_t> Resolve(const Asn1String* value) {
    if (value) {
        const auto parsed = Parse(*value);
        if (!parsed) return std::nullopt;
        return parsed->seconds;
    }
    const auto now = time_nid_postfix(nullptr);
    if (now < DateSeconds(0, 1, 1) || now >= DateSeconds(10000, 1, 1)) return std::nullopt;
    return now;
}

} // namespace

extern "C" {

Asn1String* APS5_VABI ASN1_TIME_new_nid_postfix() {
    auto* value = static_cast<Asn1String*>(calloc_nid_postfix(1, sizeof(Asn1String)));
    if (!value) {
        LibreSslPutError_nid_no_patch(13, 0xfff, 65);
        LibreSslPutError_nid_no_patch(13, 0xfff, 65);
        return nullptr;
    }
    value->type = -1;
    value->flags = 0x40;
    return value;
}

int APS5_VABI ASN1_TIME_diff_nid_postfix(int* days, int* seconds, const Asn1String* from, const Asn1String* to) {
    const auto first = Resolve(from);
    if (!first) return 0;
    const auto second = Resolve(to);
    if (!second) return 0;
    if (!days || !seconds) throw std::invalid_argument("ASN1_TIME_diff: null output");
    const auto difference = *second - *first;
    *seconds = static_cast<int>(difference % 86400);
    *days = static_cast<int>(difference / 86400);
    return 1;
}

int APS5_VABI X509_cmp_current_time_nid_postfix(const Asn1String* value) {
    if (!value) return 0;
    const auto parsed = Parse(*value);
    if (!parsed) return 0;
    if (value->type != 0 && value->type != parsed->type) return 0;
    if (parsed->type != (parsed->year < 2050 ? 23 : 24)) return 0;
    return parsed->seconds <= time_nid_postfix(nullptr) ? -1 : 1;
}

}
