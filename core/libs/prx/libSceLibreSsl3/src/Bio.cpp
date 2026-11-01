#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include <stdexcept>

namespace {

template<class T>
T& Required(T* value) {
    if (!value) throw std::invalid_argument("LibreSSL3 BIO: null object");
    return *value;
}

} // namespace

extern "C" {

void APS5_VABI BIO_clear_flags_nid_postfix(LibreSsl3Bio* bio, int flags) {
    Required(bio).flags &= ~flags;
}

void APS5_VABI BIO_set_flags_nid_postfix(LibreSsl3Bio* bio, int flags) {
    Required(bio).flags |= flags;
}

void APS5_VABI BIO_set_init_nid_postfix(LibreSsl3Bio* bio, int initialized) {
    Required(bio).initialized = initialized;
}

int APS5_VABI BIO_get_shutdown_nid_postfix(LibreSsl3Bio* bio) {
    return Required(bio).shutdown;
}

void APS5_VABI BIO_set_shutdown_nid_postfix(LibreSsl3Bio* bio, int shutdown) {
    Required(bio).shutdown = shutdown;
}

void* APS5_VABI BIO_get_data_nid_postfix(LibreSsl3Bio* bio) {
    return Required(bio).data;
}

void APS5_VABI BIO_set_data_nid_postfix(LibreSsl3Bio* bio, void* data) {
    Required(bio).data = data;
}

LibreSsl3BioMethod* APS5_VABI BIO_meth_new_nid_postfix(int type, const char* name) {
    auto* method = static_cast<LibreSsl3BioMethod*>(calloc_nid_postfix(1, sizeof(LibreSsl3BioMethod)));
    if (!method) return nullptr;
    method->type = type;
    method->name = name;
    return method;
}

void APS5_VABI BIO_meth_free_nid_postfix(LibreSsl3BioMethod* method) {
    free_nid_postfix(method);
}

int APS5_VABI BIO_meth_set_write_nid_postfix(LibreSsl3BioMethod* method, LibreSsl3BioWrite callback) {
    Required(method).write = callback;
    return 1;
}

int APS5_VABI BIO_meth_set_read_nid_postfix(LibreSsl3BioMethod* method, LibreSsl3BioRead callback) {
    Required(method).read = callback;
    return 1;
}

int APS5_VABI BIO_meth_set_ctrl_nid_postfix(LibreSsl3BioMethod* method, LibreSsl3BioControl callback) {
    Required(method).control = callback;
    return 1;
}

int APS5_VABI BIO_meth_set_create_nid_postfix(LibreSsl3BioMethod* method, LibreSsl3BioLifecycle callback) {
    Required(method).create = callback;
    return 1;
}

int APS5_VABI BIO_meth_set_destroy_nid_postfix(LibreSsl3BioMethod* method, LibreSsl3BioLifecycle callback) {
    Required(method).destroy = callback;
    return 1;
}

}
