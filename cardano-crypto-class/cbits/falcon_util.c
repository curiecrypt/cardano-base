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

size_t cardano_falcon_det512_pubkey_size(void)
{
  return FALCON_DET512_PUBKEY_SIZE;
}

size_t cardano_falcon_det512_privkey_size(void)
{
  return FALCON_DET512_PRIVKEY_SIZE;
}

size_t cardano_falcon_det512_sig_size(void)
{
  return FALCON_DET512_SIG_CT_SIZE;
}
