#pragma once

/*
 * Sizes for the Falcon-512 helpers in falcon_util.c, which wrap the vendored
 * Falcon round 3 reference implementation in cbits/falcon.
 *
 * The Haskell binding uses these as type-level sizes (PinnedSizedBytes), so
 * this header holds only #define directives. falcon_util.c checks every value
 * against the vendored FALCON_* macros with static_assert, so a mismatch
 * fails the build.
 */

/* Encoded public (verification) key. */
#define CARDANO_FALCON512_PUBKEY_SIZE 897

/* Encoded private (signing) key. */
#define CARDANO_FALCON512_PRIVKEY_SIZE 1281

/* Signature in the fixed-size padded format. */
#define CARDANO_FALCON512_SIG_SIZE 666

/* Scratch buffers the caller provides to each helper. */
#define CARDANO_FALCON512_TMP_KEYGEN_SIZE 15879
#define CARDANO_FALCON512_TMP_MAKEPUB_SIZE 3073
#define CARDANO_FALCON512_TMP_SIGN_SIZE 39943
#define CARDANO_FALCON512_TMP_VERIFY_SIZE 4097
