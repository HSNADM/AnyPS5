#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <source_location>
#include <stdexcept>

namespace {

void Check(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "BIO check failed at line %u\n", location.line());
    std::abort();
}

template<class T, class F>
void ChangesOnly(T& value, std::size_t offset, std::size_t length, F action) {
    std::array<unsigned char, sizeof(T)> before{};
    std::memcpy(before.data(), &value, sizeof(T));
    action();
    const auto* after = reinterpret_cast<const unsigned char*>(&value);
    for (std::size_t index = 0; index < sizeof(T); ++index)
        if (index < offset || index >= offset + length) Check(before[index] == after[index]);
}

template<class F>
void RejectsNull(F action) {
    bool threw = false;
    try { action(); } catch (const std::invalid_argument&) { threw = true; }
    Check(threw);
}

void Accessors() {
    struct Guarded { std::array<unsigned char, 16> left; LibreSsl3Bio bio; std::array<unsigned char, 16> right; } guarded{};
    guarded.left.fill(0xA5);
    guarded.right.fill(0x5A);
    auto& bio = guarded.bio;
    bio.references = 31;
    bio.retryReason = 79;
    bio.descriptor = -23;
    bio.bytesRead = 0x123456789ABCDEF0;
    bio.bytesWritten = 0xFEDCBA9876543210;
    const std::array<int, 7> values{0, 1, -1, 0x55555555, static_cast<int>(0xAAAAAAAAu), std::numeric_limits<int>::min(), std::numeric_limits<int>::max()};
    for (int initial : values) {
        for (int mask : values) {
            bio.flags = initial;
            ChangesOnly(bio, 40, 4, [&] { BIO_set_flags_nid_postfix(&bio, mask); });
            Check(bio.flags == (initial | mask));
            ChangesOnly(bio, 40, 4, [&] { BIO_clear_flags_nid_postfix(&bio, mask); });
            Check(bio.flags == (initial & ~mask));
        }
        ChangesOnly(bio, 32, 4, [&] { BIO_set_init_nid_postfix(&bio, initial); });
        Check(bio.initialized == initial);
        ChangesOnly(bio, 36, 4, [&] { BIO_set_shutdown_nid_postfix(&bio, initial); });
        ChangesOnly(bio, 0, 0, [&] { Check(BIO_get_shutdown_nid_postfix(&bio) == initial); });
    }
    std::array<int, 3> data{11, 17, 23};
    for (void* pointer : {static_cast<void*>(nullptr), static_cast<void*>(data.data()), static_cast<void*>(&bio)}) {
        ChangesOnly(bio, 56, 8, [&] { BIO_set_data_nid_postfix(&bio, pointer); });
        ChangesOnly(bio, 0, 0, [&] { Check(BIO_get_data_nid_postfix(&bio) == pointer); });
    }
    Check(data == std::array<int, 3>{11, 17, 23});
    for (auto byte : guarded.left) Check(byte == 0xA5);
    for (auto byte : guarded.right) Check(byte == 0x5A);
    RejectsNull([] { BIO_clear_flags_nid_postfix(nullptr, -1); });
    RejectsNull([] { BIO_set_flags_nid_postfix(nullptr, -1); });
    RejectsNull([] { BIO_set_init_nid_postfix(nullptr, -7); });
    RejectsNull([] { BIO_get_shutdown_nid_postfix(nullptr); });
    RejectsNull([] { BIO_set_shutdown_nid_postfix(nullptr, 0); });
    RejectsNull([] { BIO_get_data_nid_postfix(nullptr); });
    RejectsNull([] { BIO_set_data_nid_postfix(nullptr, nullptr); });
}

std::size_t allocations = 0;
std::size_t frees = 0;
std::size_t callbackCalls = 0;
bool failAllocation = false;
void* liveAllocation = nullptr;

void* APS5_VABI UnexpectedAllocate_nid_no_patch(std::size_t) { throw std::runtime_error("unexpected malloc"); }
void* APS5_VABI UnexpectedReallocate_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void* APS5_VABI AllocateZeroed_nid_no_patch(std::size_t count, std::size_t size) {
    Check(count == 1 && size == 80 && liveAllocation == nullptr);
    ++allocations;
    if (failAllocation) return nullptr;
    auto* memory = static_cast<unsigned char*>(std::malloc(size + 32));
    Check(memory != nullptr);
    std::memset(memory, 0xA5, size + 32);
    liveAllocation = memory + 16;
    std::memset(liveAllocation, 0, size);
    return liveAllocation;
}

void APS5_VABI Release_nid_no_patch(void* pointer) {
    if (!pointer) return;
    Check(pointer == liveAllocation);
    auto* memory = static_cast<unsigned char*>(pointer) - 16;
    for (std::size_t index = 0; index < 16; ++index) Check(memory[index] == 0xA5 && memory[96 + index] == 0xA5);
    std::free(memory);
    liveAllocation = nullptr;
    ++frees;
}

int APS5_VABI Write_nid_no_patch(LibreSsl3Bio* bio, const char* data, int size) {
    ++callbackCalls;
    Check(bio && data && data[0] == 'w' && size == -37);
    return 19;
}

int APS5_VABI Read_nid_no_patch(LibreSsl3Bio* bio, char* data, int size) {
    ++callbackCalls;
    Check(bio && data && size == 3);
    std::memcpy(data, "ok", 3);
    return 2;
}

std::int64_t APS5_VABI Control_nid_no_patch(LibreSsl3Bio* bio, int command, std::int64_t argument, void* pointer) {
    ++callbackCalls;
    Check(bio && command == -31 && argument == -0x123456789ABC && pointer == bio);
    return 0x123456789ABCDE;
}

int APS5_VABI Create_nid_no_patch(LibreSsl3Bio* bio) { ++callbackCalls; Check(bio != nullptr); return 7; }
int APS5_VABI Destroy_nid_no_patch(LibreSsl3Bio* bio) { ++callbackCalls; Check(bio != nullptr); return -9; }

void Methods() {
    std::array<void*, 10> api{};
    api[0] = reinterpret_cast<void*>(UnexpectedAllocate_nid_no_patch);
    api[1] = reinterpret_cast<void*>(Release_nid_no_patch);
    api[2] = reinterpret_cast<void*>(AllocateZeroed_nid_no_patch);
    api[3] = reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch);
    api[4] = reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch);
    api[5] = reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch);
    api[6] = reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch);
    ApplicationHeapRegister_nid_no_patch(api.data());
    char name[] = "custom method";
    for (int type : {0, -1, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
        auto* method = BIO_meth_new_nid_postfix(type, name);
        Check(method && method == liveAllocation && method->type == type && method->name == name);
        Check(!method->write && !method->read && !method->puts && !method->gets && !method->control && !method->create && !method->destroy && !method->callbackControl);
        ChangesOnly(*method, 16, 8, [&] { Check(BIO_meth_set_write_nid_postfix(method, Write_nid_no_patch) == 1); });
        ChangesOnly(*method, 24, 8, [&] { Check(BIO_meth_set_read_nid_postfix(method, Read_nid_no_patch) == 1); });
        ChangesOnly(*method, 48, 8, [&] { Check(BIO_meth_set_ctrl_nid_postfix(method, Control_nid_no_patch) == 1); });
        ChangesOnly(*method, 56, 8, [&] { Check(BIO_meth_set_create_nid_postfix(method, Create_nid_no_patch) == 1); });
        ChangesOnly(*method, 64, 8, [&] { Check(BIO_meth_set_destroy_nid_postfix(method, Destroy_nid_no_patch) == 1); });
        Check(callbackCalls == 0);
        LibreSsl3Bio bio{};
        char data[3]{};
        Check(method->write(&bio, "w", -37) == 19);
        Check(method->read(&bio, data, 3) == 2 && std::strcmp(data, "ok") == 0);
        Check(method->control(&bio, -31, -0x123456789ABC, &bio) == 0x123456789ABCDE);
        Check(method->create(&bio) == 7 && method->destroy(&bio) == -9 && callbackCalls == 5);
        callbackCalls = 0;
        Check(BIO_meth_set_write_nid_postfix(method, nullptr) == 1 && !method->write);
        Check(BIO_meth_set_read_nid_postfix(method, nullptr) == 1 && !method->read);
        Check(BIO_meth_set_ctrl_nid_postfix(method, nullptr) == 1 && !method->control);
        Check(BIO_meth_set_create_nid_postfix(method, nullptr) == 1 && !method->create);
        Check(BIO_meth_set_destroy_nid_postfix(method, nullptr) == 1 && !method->destroy);
        name[0] = name[0] == 'c' ? 'C' : 'c';
        Check(method->name[0] == name[0]);
        BIO_meth_free_nid_postfix(method);
        Check(!liveAllocation && allocations == frees);
    }
    auto* unnamed = BIO_meth_new_nid_postfix(-41, nullptr);
    Check(unnamed && unnamed->type == -41 && !unnamed->name);
    BIO_meth_free_nid_postfix(unnamed);
    BIO_meth_free_nid_postfix(nullptr);
    Check(allocations == 5 && frees == 5 && !liveAllocation);
    failAllocation = true;
    Check(BIO_meth_new_nid_postfix(31, name) == nullptr && !liveAllocation && frees == 5);
    failAllocation = false;
    RejectsNull([] { BIO_meth_set_write_nid_postfix(nullptr, Write_nid_no_patch); });
    RejectsNull([] { BIO_meth_set_read_nid_postfix(nullptr, Read_nid_no_patch); });
    RejectsNull([] { BIO_meth_set_ctrl_nid_postfix(nullptr, Control_nid_no_patch); });
    RejectsNull([] { BIO_meth_set_create_nid_postfix(nullptr, Create_nid_no_patch); });
    RejectsNull([] { BIO_meth_set_destroy_nid_postfix(nullptr, Destroy_nid_no_patch); });
}

} // namespace

int main() {
    Accessors();
    Methods();
    std::puts("BIO state, callback ABI, method ownership and allocation-failure checks passed");
}
