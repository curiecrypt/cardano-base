#pragma once

#include <stddef.h>

/*
 * Helpers around the vendored deterministic Falcon code in cbits/falcon
 * (algorand/falcon), for a foreign-language binding (here: Haskell).
 *
 * Only Falcon-det512 (n = 512) is exposed. The helpers build on the public
 * API of the vendored code (falcon.h and deterministic.h) and never call its
 * internal falcon_inner_* functions, so that re-vendoring a newer upstream
 * cannot silently change what they rely on.
 *
 * The binding allocates all memory itself (for Haskell: RTS-managed pinned
 * memory), so every function works on caller-allocated buffers. The sizes of
 * those buffers are facts of the C code and are owned by the size functions
 * below: a binding must never hardcode them.
 */

/* Size in bytes of an encoded Falcon-det512 public (verification) key. */
size_t cardano_falcon_det512_pubkey_size(void);

/* Size in bytes of an encoded Falcon-det512 private (signing) key. */
size_t cardano_falcon_det512_privkey_size(void);

/* Size in bytes of a Falcon-det512 signature in the fixed-size CT format. */
size_t cardano_falcon_det512_sig_size(void);
