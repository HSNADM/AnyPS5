# libSceLibreSsl3 technical debt

### Unknown function info

- [libSceLibreSsl3 pending exports](../../../core/libs/prx/libSceLibreSsl3/Export.cpp) - The remaining throwing callable exports come from the [PS5 3.20 export table](https://github.com/DNNDHH/PS5-3.20_Libs/blob/b2a77c09cd71c01f34c790cfbe98c751a13262ad/libSceLibreSsl3.c), cross-checked against the same module in PS5 firmware 13.60. Their signatures and behaviour are unverified; the declarations use the no-parameter unknown-signature convention and throw through `NotImplemented_nid_no_patch`.

### Functional

- [RSA_check_key and RSA_up_ref](../../../core/libs/prx/libSceLibreSsl3/Export.cpp) - console RSA layout and results are unverified. These operate on the parent libSceLibreSsl key representation, as the existing shared digest functions do. Validation follows LibreSSL 2.5.4 [rsa_chk.c](https://github.com/libressl/openbsd/blob/2e2c612066aa993717528a0249c15c51128d61cb/src/lib/libcrypto/rsa/rsa_chk.c), using 40 mbedtls Miller-Rabin rounds for each prime instead of LibreSSL's configured primality test. Reference counts use host atomics instead of registered CRYPTO locking callbacks.

- [CRYPTO_memcmp](../../../core/libs/prx/libSceLibreSsl3/Export.cpp) follows the public [LibreSSL signature and equality contract](https://man.openbsd.org/CRYPTO_memcmp.3), without PS5 verification. The exact nonzero result for unequal buffers is unspecified by that contract. Content-independent execution of its volatile byte reads still depends on the compiler; inspect optimized code when changing toolchains. Closes when: measured on a PS5 and the supported toolchains' generated code is checked.
- [MD5 and SHA1](../../../core/libs/prx/libSceLibreSsl3/src/Digest.cpp) (libSceLibreSsl3) - follow LibreSSL's [md5.c, sha1.c](https://github.com/libressl/openbsd/tree/bc9483725c5815efb64b6d9acc52fc5fba139212/src/lib/libcrypto) and hash through libSceLibreSsl's `MD5_*` and `SHA1_*`. A null digest buffer throws: LibreSSL up to 3.8 returns a static buffer, later versions do not check it. Nothing is checked on the console
