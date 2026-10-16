#pragma once

/*
 * Constants for the Falcon-det512 helpers in falcon_util.c, which wrap the
 * vendored deterministic Falcon code in cbits/falcon (algorand/falcon).
 *
 * This header is shared with the Haskell binding, which includes it through
 * CPP to use the sizes at the type level (PinnedSizedBytes). It must therefore
 * contain only #define directives and C-style comments: no declarations and no
 * line comments. falcon_util.c checks the key and signature sizes and the error
 * codes against the vendored code with static_assert, so a mismatch fails the
 * build.
 */

/* Encoded Falcon-det512 public (verification) key, in bytes. */
#define CARDANO_FALCON_DET512_PUBKEY_SIZE 897

/* Encoded Falcon-det512 private (signing) key, in bytes. */
#define CARDANO_FALCON_DET512_PRIVKEY_SIZE 1281

/* Falcon-det512 signature in the fixed-size CT format, in bytes. */
#define CARDANO_FALCON_DET512_SIG_SIZE 770

/*
 * Seed size, in bytes, used by the Haskell binding for key generation. This is
 * a choice of the binding (256 bits of entropy), not a fact of the vendored
 * code, which accepts seeds of any length.
 */
#define CARDANO_FALCON_DET512_SEED_SIZE 32

/* Return codes of the helpers: 0 on success, or one of the FALCON_ERR_* codes. */
#define CARDANO_FALCON_SUCCESS 0
#define CARDANO_FALCON_ERR_RANDOM (-1)
#define CARDANO_FALCON_ERR_SIZE (-2)
#define CARDANO_FALCON_ERR_FORMAT (-3)
#define CARDANO_FALCON_ERR_BADSIG (-4)
#define CARDANO_FALCON_ERR_BADARG (-5)
#define CARDANO_FALCON_ERR_INTERNAL (-6)
