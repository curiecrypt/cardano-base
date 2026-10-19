#include <assert.h>
#include <sodium.h>

#include "falcon_util.h"

#include "falcon/config.h"
#include "falcon/deterministic.h"

/*
 * Deterministic signing is only safe if a given key and message always give
 * the same signature, on every platform: two different signatures for the
 * same hash point leak the private key. The vendored config.h ensures this by
 * emulating floating point with integer arithmetic (FALCON_FPEMU) and by
 * disabling native floating point, fused multiply-add and AVX2, whose results
 * can differ between CPUs and compilers. Refuse to build if a re-vendored
 * config.h ever changes that. A macro missing from config.h evaluates to 0
 * here, so this check fails closed.
 */
#if !FALCON_FPEMU || FALCON_FPNATIVE || FALCON_FMA || FALCON_AVX2
#error "cbits/falcon must be built with FALCON_FPEMU = 1 and FALCON_FPNATIVE = FALCON_FMA = FALCON_AVX2 = 0"
#endif

/*
 * Verify at compile time that the constants in falcon_util.h, which the
 * Haskell binding uses as type-level sizes and return codes, match the
 * vendored code.
 */
static_assert(FALCON_DET512_PUBKEY_SIZE == CARDANO_FALCON_DET512_PUBKEY_SIZE,
              "Falcon-det512 public key size mismatch");
static_assert(FALCON_DET512_PRIVKEY_SIZE == CARDANO_FALCON_DET512_PRIVKEY_SIZE,
              "Falcon-det512 private key size mismatch");
static_assert(FALCON_DET512_SIG_CT_SIZE == CARDANO_FALCON_DET512_SIG_SIZE,
              "Falcon-det512 CT signature size mismatch");

static_assert(FALCON_ERR_RANDOM == CARDANO_FALCON_ERR_RANDOM, "FALCON_ERR_RANDOM mismatch");
static_assert(FALCON_ERR_SIZE == CARDANO_FALCON_ERR_SIZE, "FALCON_ERR_SIZE mismatch");
static_assert(FALCON_ERR_FORMAT == CARDANO_FALCON_ERR_FORMAT, "FALCON_ERR_FORMAT mismatch");
static_assert(FALCON_ERR_BADSIG == CARDANO_FALCON_ERR_BADSIG, "FALCON_ERR_BADSIG mismatch");
static_assert(FALCON_ERR_BADARG == CARDANO_FALCON_ERR_BADARG, "FALCON_ERR_BADARG mismatch");
static_assert(FALCON_ERR_INTERNAL == CARDANO_FALCON_ERR_INTERNAL, "FALCON_ERR_INTERNAL mismatch");

/*
 * Generate a Falcon-det512 key pair from a seed.
 *
 * The seed (seed_len bytes, of any length) initializes a SHAKE256-based PRNG
 * from which falcon_det512_keygen draws all of its randomness, so the same
 * seed always gives the same key pair. The caller provides privkey
 * (CARDANO_FALCON_DET512_PRIVKEY_SIZE bytes) and pubkey
 * (CARDANO_FALCON_DET512_PUBKEY_SIZE bytes). The PRNG state, from which the
 * key pair could be regenerated, is wiped before returning. Scratch memory
 * inside falcon_det512_keygen itself is not wiped, as that would require
 * modifying the vendored code.
 *
 * Returns CARDANO_FALCON_SUCCESS, or a negative CARDANO_FALCON_ERR_* code.
 */
int cardano_falcon_det512_keygen(const uint8_t *seed, size_t seed_len,
                                 uint8_t *privkey, uint8_t *pubkey)
{
  shake256_context rng;
  shake256_init_prng_from_seed(&rng, seed, seed_len);
  int r = falcon_det512_keygen(&rng, privkey, pubkey);
  sodium_memzero(&rng, sizeof rng);
  return r;
}

/*
 * Recompute the public key of a Falcon-det512 private key.
 *
 * The caller provides privkey (CARDANO_FALCON_DET512_PRIVKEY_SIZE bytes) and
 * pubkey (CARDANO_FALCON_DET512_PUBKEY_SIZE bytes). falcon_make_public
 * rejects a private key whose header or encoding is invalid. Its scratch
 * buffer holds the decoded secret polynomials and is wiped before returning.
 *
 * Returns CARDANO_FALCON_SUCCESS, or a negative CARDANO_FALCON_ERR_* code.
 */
int cardano_falcon_det512_derive_pubkey(const uint8_t *privkey, uint8_t *pubkey)
{
  uint8_t tmp[FALCON_TMPSIZE_MAKEPUB(FALCON_DET512_LOGN)];
  int r = falcon_make_public(pubkey, CARDANO_FALCON_DET512_PUBKEY_SIZE,
                             privkey, CARDANO_FALCON_DET512_PRIVKEY_SIZE,
                             tmp, sizeof tmp);
  sodium_memzero(tmp, sizeof tmp);
  return r;
}

/*
 * Sign a message with a Falcon-det512 private key, producing a signature in
 * the fixed-size CT format.
 *
 * The deterministic Falcon specification has a single signing path, which
 * produces the variable-length compressed format; there is no deterministic
 * CT signing function. The compressed signature is therefore converted to CT,
 * a lossless re-encoding of the same signature (this is also how the CT
 * known-answer tests of algorand/falcon are produced). The caller provides
 * privkey (CARDANO_FALCON_DET512_PRIVKEY_SIZE bytes), msg (msg_len bytes) and
 * sig (CARDANO_FALCON_DET512_SIG_SIZE bytes). As for key generation, the
 * secret-dependent scratch memory inside the vendored signing function is not
 * wiped.
 *
 * Returns CARDANO_FALCON_SUCCESS, or a negative CARDANO_FALCON_ERR_* code.
 */
int cardano_falcon_det512_sign(const uint8_t *privkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig)
{
  uint8_t sig_compressed[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
  size_t sig_compressed_len = sizeof sig_compressed;
  int r = falcon_det512_sign_compressed(sig_compressed, &sig_compressed_len,
                                        privkey, msg, msg_len);
  if (r != 0) {
    return r;
  }
  return falcon_det512_convert_compressed_to_ct(sig, sig_compressed,
                                                sig_compressed_len);
}

/*
 * Verify a Falcon-det512 signature in CT format.
 *
 * falcon_det512_verify_ct checks the header byte, then rebuilds the salt from
 * whatever salt version the signature carries. Only the salt version defined
 * by the current specification is accepted here, as Algorand does. The caller
 * provides sig (CARDANO_FALCON_DET512_SIG_SIZE bytes), pubkey
 * (CARDANO_FALCON_DET512_PUBKEY_SIZE bytes) and msg (msg_len bytes).
 *
 * Returns CARDANO_FALCON_SUCCESS if the signature is valid, or a negative
 * CARDANO_FALCON_ERR_* code.
 */
int cardano_falcon_det512_verify(const uint8_t *sig, const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len)
{
  if (falcon_det512_get_salt_version(sig) != FALCON_DET512_CURRENT_SALT_VERSION) {
    return CARDANO_FALCON_ERR_BADSIG;
  }
  return falcon_det512_verify_ct(sig, pubkey, msg, msg_len);
}
