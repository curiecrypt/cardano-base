#include <assert.h>

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
