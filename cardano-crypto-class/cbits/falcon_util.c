#include "falcon_util.h"
#include "falcon/falcon.h"

#include <assert.h>
#include <stdint.h>

/*
 * Falcon-512 helpers for the Haskell binding, over the unmodified Falcon
 * round 3 reference implementation in cbits/falcon.
 *
 * - The degree is fixed to 512 (logn = 9) and signatures use the padded
 *   format, so every object has a fixed size.
 * - The caller allocates every buffer, scratch space included; nothing here
 *   allocates.
 * - Every function returns 0 on success or a negative FALCON_ERR_* code.
 */

#define LOGN 9

/*
 * Verify at compile time that the sizes in falcon_util.h match the vendored
 * code, following the cbits/blst_util.c pattern.
 */
static_assert(FALCON_PUBKEY_SIZE(LOGN) == CARDANO_FALCON512_PUBKEY_SIZE, "Falcon-512 public key size mismatch");
static_assert(FALCON_PRIVKEY_SIZE(LOGN) == CARDANO_FALCON512_PRIVKEY_SIZE, "Falcon-512 private key size mismatch");
static_assert(FALCON_SIG_PADDED_SIZE(LOGN) == CARDANO_FALCON512_SIG_SIZE, "Falcon-512 padded signature size mismatch");
static_assert(FALCON_TMPSIZE_KEYGEN(LOGN) == CARDANO_FALCON512_TMP_KEYGEN_SIZE, "Falcon-512 keygen scratch size mismatch");
static_assert(FALCON_TMPSIZE_MAKEPUB(LOGN) == CARDANO_FALCON512_TMP_MAKEPUB_SIZE, "Falcon-512 makepub scratch size mismatch");
static_assert(FALCON_TMPSIZE_SIGNDYN(LOGN) == CARDANO_FALCON512_TMP_SIGN_SIZE, "Falcon-512 sign scratch size mismatch");
static_assert(FALCON_TMPSIZE_VERIFY(LOGN) == CARDANO_FALCON512_TMP_VERIFY_SIZE, "Falcon-512 verify scratch size mismatch");

/*
 * Signing is deterministic (see cardano_falcon512_sign), so the same key and
 * message must give the same signature on every platform. Native floating
 * point does not guarantee that (FMA contraction, x87 precision), so the
 * build must select the emulated, integer-only implementation.
 */
#if !defined FALCON_FPEMU || !FALCON_FPEMU
#error "falcon_util.c requires FALCON_FPEMU=1 (set in cardano-crypto-class.cabal)"
#endif
#if (defined FALCON_FMA && FALCON_FMA) || (defined FALCON_AVX2 && FALCON_AVX2)
#error "falcon_util.c requires FALCON_FMA and FALCON_AVX2 to be off"
#endif

/* Domain separation tag for the signing randomness. */
static const char SIGN_TAG[] = "cardano-crypto-class:falcon512:sign:v1";

/*
 * Zero a buffer that held secret material. The volatile pointer stops the
 * compiler from removing the writes as dead stores.
 */
static void wipe(void *p, size_t len) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (len--) {
    *v++ = 0;
  }
}

/*
 * Generate a key pair from a seed. Deterministic in the seed: the seed
 * initializes the SHAKE256-based PRNG that falcon_keygen_make draws from.
 *
 * Buffers: sk CARDANO_FALCON512_PRIVKEY_SIZE, pk CARDANO_FALCON512_PUBKEY_SIZE,
 * tmp CARDANO_FALCON512_TMP_KEYGEN_SIZE bytes. tmp is wiped before returning.
 */
int cardano_falcon512_keygen(const uint8_t *seed, size_t seed_len,
                             uint8_t *sk, uint8_t *pk, uint8_t *tmp) {
  shake256_context rng;
  int r;

  shake256_init_prng_from_seed(&rng, seed, seed_len);
  r = falcon_keygen_make(&rng, LOGN,
                         sk, CARDANO_FALCON512_PRIVKEY_SIZE,
                         pk, CARDANO_FALCON512_PUBKEY_SIZE,
                         tmp, CARDANO_FALCON512_TMP_KEYGEN_SIZE);
  wipe(&rng, sizeof rng);
  wipe(tmp, CARDANO_FALCON512_TMP_KEYGEN_SIZE);
  return r;
}

/*
 * Recompute the public key from a private key.
 *
 * Buffers: pk CARDANO_FALCON512_PUBKEY_SIZE, sk CARDANO_FALCON512_PRIVKEY_SIZE,
 * tmp CARDANO_FALCON512_TMP_MAKEPUB_SIZE bytes. tmp is wiped before returning.
 */
int cardano_falcon512_make_public(uint8_t *pk, const uint8_t *sk, uint8_t *tmp) {
  int r;

  r = falcon_make_public(pk, CARDANO_FALCON512_PUBKEY_SIZE,
                         sk, CARDANO_FALCON512_PRIVKEY_SIZE,
                         tmp, CARDANO_FALCON512_TMP_MAKEPUB_SIZE);
  wipe(tmp, CARDANO_FALCON512_TMP_MAKEPUB_SIZE);
  return r;
}

/*
 * Sign a message with a padded Falcon-512 signature.
 *
 * Deterministic: the PRNG that falcon_sign_dyn draws its 40-byte nonce and
 * its Gaussian samples from is SHAKE256(SIGN_TAG || sk || msg). The private
 * key has a fixed length, so this input encoding is unambiguous. The same
 * key and message always give the same signature, including when the padded
 * encoding needs a retry: the retry draws from the same deterministic stream.
 *
 * This derandomization is a choice of this binding, not part of the Falcon
 * specification. The resulting signature is an ordinary padded Falcon-512
 * signature, accepted by any Falcon-512 verifier.
 *
 * Buffers: sig CARDANO_FALCON512_SIG_SIZE, sk CARDANO_FALCON512_PRIVKEY_SIZE,
 * tmp CARDANO_FALCON512_TMP_SIGN_SIZE bytes. tmp is wiped before returning.
 */
int cardano_falcon512_sign(uint8_t *sig, const uint8_t *sk,
                           const uint8_t *msg, size_t msg_len, uint8_t *tmp) {
  shake256_context rng;
  size_t sig_len = CARDANO_FALCON512_SIG_SIZE;
  int r;

  shake256_init(&rng);
  shake256_inject(&rng, SIGN_TAG, sizeof SIGN_TAG - 1);
  shake256_inject(&rng, sk, CARDANO_FALCON512_PRIVKEY_SIZE);
  shake256_inject(&rng, msg, msg_len);
  shake256_flip(&rng);

  r = falcon_sign_dyn(&rng, sig, &sig_len, FALCON_SIG_PADDED,
                      sk, CARDANO_FALCON512_PRIVKEY_SIZE,
                      msg, msg_len,
                      tmp, CARDANO_FALCON512_TMP_SIGN_SIZE);
  wipe(&rng, sizeof rng);
  wipe(tmp, CARDANO_FALCON512_TMP_SIGN_SIZE);
  if (r == 0 && sig_len != CARDANO_FALCON512_SIG_SIZE) {
    return FALCON_ERR_INTERNAL;
  }
  return r;
}

/*
 * Verify a padded Falcon-512 signature. Returns 0 if valid.
 *
 * Buffers: sig CARDANO_FALCON512_SIG_SIZE, pk CARDANO_FALCON512_PUBKEY_SIZE,
 * tmp CARDANO_FALCON512_TMP_VERIFY_SIZE bytes.
 */
int cardano_falcon512_verify(const uint8_t *sig, const uint8_t *pk,
                             const uint8_t *msg, size_t msg_len, uint8_t *tmp) {
  return falcon_verify(sig, CARDANO_FALCON512_SIG_SIZE, FALCON_SIG_PADDED,
                       pk, CARDANO_FALCON512_PUBKEY_SIZE,
                       msg, msg_len,
                       tmp, CARDANO_FALCON512_TMP_VERIFY_SIZE);
}
