#include "prx/libSceLibreSsl3/include/Api.hpp"
#include <stdexcept>

extern "C" {

void APS5_VABI RSA_get0_key_nid_postfix(const LibreSsl3Rsa* key, const LibreSsl3Bignum** n, const LibreSsl3Bignum** e, const LibreSsl3Bignum** d) {
    if (!n && !e && !d) return;
    if (!key) throw std::invalid_argument("RSA_get0_key: null key");
    if (n) *n = static_cast<const LibreSsl3Bignum*>(key->n);
    if (e) *e = static_cast<const LibreSsl3Bignum*>(key->e);
    if (d) *d = static_cast<const LibreSsl3Bignum*>(key->d);
}

void APS5_VABI RSA_get0_factors_nid_postfix(const LibreSsl3Rsa* key, const LibreSsl3Bignum** p, const LibreSsl3Bignum** q) {
    if (!p && !q) return;
    if (!key) throw std::invalid_argument("RSA_get0_factors: null key");
    if (p) *p = static_cast<const LibreSsl3Bignum*>(key->p);
    if (q) *q = static_cast<const LibreSsl3Bignum*>(key->q);
}

void APS5_VABI RSA_get0_crt_params_nid_postfix(const LibreSsl3Rsa* key, const LibreSsl3Bignum** dmp1, const LibreSsl3Bignum** dmq1, const LibreSsl3Bignum** iqmp) {
    if (!dmp1 && !dmq1 && !iqmp) return;
    if (!key) throw std::invalid_argument("RSA_get0_crt_params: null key");
    if (dmp1) *dmp1 = static_cast<const LibreSsl3Bignum*>(key->dmp1);
    if (dmq1) *dmq1 = static_cast<const LibreSsl3Bignum*>(key->dmq1);
    if (iqmp) *iqmp = static_cast<const LibreSsl3Bignum*>(key->iqmp);
}

}
