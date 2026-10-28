#include "falcon_util.h"
#include "falcon/falcon.h"
#include "falcon/inner.h"

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
 * Scratch layout for cardano_falcon512_check_private: alignment slack, three
 * fpr polynomials (the second also serves as complete_private's scratch), and
 * f, g, F, G as int8. It reuses the keygen scratch size.
 */
#define CHECK_N ((size_t)1 << LOGN)
#define CHECK_TMP_NEEDED (sizeof(fpr) - 1 + 3 * CHECK_N * sizeof(fpr) + 4 * CHECK_N)
static_assert(CHECK_TMP_NEEDED <= CARDANO_FALCON512_TMP_KEYGEN_SIZE, "Falcon-512 check scratch too small");

/*
 * Check that an encoded private key is one Falcon key generation could have
 * produced, so that signing with it terminates as for a generated key.
 *
 * The header and length alone accept degenerate keys: for example, a header
 * followed by 0x04 and zeros decodes, gives a public key, and makes
 * falcon_sign_dyn loop forever. Key generation (keygen.c) only outputs keys
 * that pass the checks below, so a generated key always passes.
 *
 *   1. Header 0x50 + logn, and f, g, F decode with exactly the key's length.
 *      The trim decoding bounds f, g to |x| < 2^5 and F to |x| < 2^7, as
 *      keygen does.
 *   2. complete_private computes G = g F / f mod q: f is invertible mod q and
 *      |G| < 2^7.
 *   3. f G - g F = q exactly, over Z[x]/(x^n + 1). Step 2 only gives this
 *      modulo q; a key with f G - g F = 0 passes step 2 but is not a basis.
 *   4. ||(g, -f)||^2 < 1.17^2 q, the keygen bound.
 *   5. The Gram-Schmidt norm of the second basis vector is below the same
 *      bound, computed as in keygen.
 *
 * Returns 0 if the key passes, FALCON_ERR_FORMAT otherwise.
 *
 * Buffers: sk CARDANO_FALCON512_PRIVKEY_SIZE, tmp
 * CARDANO_FALCON512_TMP_KEYGEN_SIZE bytes. tmp is wiped before returning.
 */
int cardano_falcon512_check_private(const uint8_t *sk, uint8_t *tmp) {
  const size_t n = CHECK_N;
  const size_t sk_len = CARDANO_FALCON512_PRIVKEY_SIZE;
  fpr *rt1, *rt2, *rt3;
  int8_t *f, *g, *F, *G;
  size_t u, v;
  uint32_t norm;
  fpr bnorm;
  int r = FALCON_ERR_FORMAT;

  rt1 = (fpr *)(tmp + ((sizeof(fpr) - ((uintptr_t)tmp % sizeof(fpr))) % sizeof(fpr)));
  rt2 = rt1 + n;
  rt3 = rt2 + n;
  f = (int8_t *)(rt3 + n);
  g = f + n;
  F = g + n;
  G = F + n;

  /* 1. Header and decoding. */
  if (sk[0] != 0x50 + LOGN) {
    goto out;
  }
  u = 1;
  v = Zf(trim_i8_decode)(f, LOGN, Zf(max_fg_bits)[LOGN], sk + u, sk_len - u);
  if (v == 0) {
    goto out;
  }
  u += v;
  v = Zf(trim_i8_decode)(g, LOGN, Zf(max_fg_bits)[LOGN], sk + u, sk_len - u);
  if (v == 0) {
    goto out;
  }
  u += v;
  v = Zf(trim_i8_decode)(F, LOGN, Zf(max_FG_bits)[LOGN], sk + u, sk_len - u);
  if (v == 0) {
    goto out;
  }
  u += v;
  if (u != sk_len) {
    goto out;
  }

  /* 2. G, with f invertible mod q and G in range. */
  if (!Zf(complete_private)(G, f, g, F, LOGN, (uint8_t *)rt2)) {
    goto out;
  }

  /*
   * 3. f G - g F = q in Z[x]/(x^n + 1), coefficient by coefficient. Each
   * term is below 31 * 127 in absolute value, so a coefficient stays below
   * 2 * 512 * 3937 < 2^22 and fits in int32_t.
   */
  for (u = 0; u < n; u++) {
    int32_t c = 0;
    for (v = 0; v < n; v++) {
      int32_t t = (int32_t)f[v] * G[(u - v) % n] - (int32_t)g[v] * F[(u - v) % n];
      c += v <= u ? t : -t;
    }
    if (c != (u == 0 ? 12289 : 0)) {
      goto out;
    }
  }

  /* 4. ||(g, -f)||^2, an integer below 2 * 512 * 31^2. */
  norm = 0;
  for (u = 0; u < n; u++) {
    norm += (uint32_t)((int32_t)f[u] * f[u]) + (uint32_t)((int32_t)g[u] * g[u]);
  }
  if (norm >= 16823) {
    goto out;
  }

  /* 5. Orthogonalized norm, the same computation as keygen.c. */
  for (u = 0; u < n; u++) {
    rt1[u] = fpr_of(f[u]);
    rt2[u] = fpr_of(g[u]);
  }
  Zf(FFT)(rt1, LOGN);
  Zf(FFT)(rt2, LOGN);
  Zf(poly_invnorm2_fft)(rt3, rt1, rt2, LOGN);
  Zf(poly_adj_fft)(rt1, LOGN);
  Zf(poly_adj_fft)(rt2, LOGN);
  Zf(poly_mulconst)(rt1, fpr_q, LOGN);
  Zf(poly_mulconst)(rt2, fpr_q, LOGN);
  Zf(poly_mul_autoadj_fft)(rt1, rt3, LOGN);
  Zf(poly_mul_autoadj_fft)(rt2, rt3, LOGN);
  Zf(iFFT)(rt1, LOGN);
  Zf(iFFT)(rt2, LOGN);
  bnorm = fpr_zero;
  for (u = 0; u < n; u++) {
    bnorm = fpr_add(bnorm, fpr_sqr(rt1[u]));
    bnorm = fpr_add(bnorm, fpr_sqr(rt2[u]));
  }
  if (!fpr_lt(bnorm, fpr_bnorm_max)) {
    goto out;
  }

  r = 0;
out:
  wipe(tmp, CARDANO_FALCON512_TMP_KEYGEN_SIZE);
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
 *
 * tmp must be 2-byte aligned. falcon.h says scratch buffers need no
 * alignment, but falcon_sign_dyn reads tmp + 4n as uint16_t without aligning
 * it first. The Haskell binding allocates tmp with allocaSized, which is
 * word-aligned.
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
