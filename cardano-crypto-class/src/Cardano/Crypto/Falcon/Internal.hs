{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}

-- | Raw FFI to the Falcon-512 helpers in @cbits/falcon_util.c@, which wrap
-- the vendored Falcon round 3 reference implementation in @cbits/falcon@.
--
-- Every fixed-size buffer is a 'SizedPtr' whose size comes from
-- @cbits/falcon_util.h@, the same constants @falcon_util.c@ checks against
-- the vendored code with @static_assert@. A size mismatch therefore fails the
-- build on the C side, and a buffer of the wrong size fails to type-check on
-- the Haskell side.
--
-- The caller allocates every buffer, scratch space included. Each function
-- returns 0 on success or a negative @FALCON_ERR_*@ code.
--
-- == Safe and unsafe calls
--
-- Key generation and signing take milliseconds, so they are @safe@ calls:
-- the GHC runtime keeps running other Haskell threads meanwhile. Verification
-- takes microseconds, so it is an @unsafe@ call, which has less overhead.
module Cardano.Crypto.Falcon.Internal (
  -- * Sizes
  FalconPubKeySize,
  FalconPrivKeySize,
  FalconSigSize,
  FalconTmpKeygenSize,
  FalconTmpMakePubSize,
  FalconTmpSignSize,
  FalconTmpVerifySize,

  -- * Direct C bindings
  c_falcon512_keygen,
  c_falcon512_make_public,
  c_falcon512_sign,
  c_falcon512_verify,
  c_falcon512_check_private,
) where

#include "falcon_util.h"

import Cardano.Foreign (SizedPtr (..))
import Data.Word (Word8)
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Ptr (Ptr)

-- | Encoded public (verification) key, in bytes.
type FalconPubKeySize = CARDANO_FALCON512_PUBKEY_SIZE

-- | Encoded private (signing) key, in bytes.
type FalconPrivKeySize = CARDANO_FALCON512_PRIVKEY_SIZE

-- | Signature in the fixed-size padded format, in bytes.
type FalconSigSize = CARDANO_FALCON512_SIG_SIZE

-- | Scratch buffer for 'c_falcon512_keygen', in bytes.
type FalconTmpKeygenSize = CARDANO_FALCON512_TMP_KEYGEN_SIZE

-- | Scratch buffer for 'c_falcon512_make_public', in bytes.
type FalconTmpMakePubSize = CARDANO_FALCON512_TMP_MAKEPUB_SIZE

-- | Scratch buffer for 'c_falcon512_sign', in bytes.
type FalconTmpSignSize = CARDANO_FALCON512_TMP_SIGN_SIZE

-- | Scratch buffer for 'c_falcon512_verify', in bytes.
type FalconTmpVerifySize = CARDANO_FALCON512_TMP_VERIFY_SIZE

-- | @c_falcon512_keygen seed seedLen sk pk tmp@: generate a key pair,
-- deterministically in the seed. Wipes @tmp@ before returning.
foreign import ccall safe "cardano_falcon512_keygen"
  c_falcon512_keygen ::
    Ptr Word8 ->
    CSize ->
    SizedPtr FalconPrivKeySize ->
    SizedPtr FalconPubKeySize ->
    SizedPtr FalconTmpKeygenSize ->
    IO CInt

-- | @c_falcon512_make_public pk sk tmp@: recompute the public key from a
-- private key. Wipes @tmp@ before returning.
foreign import ccall unsafe "cardano_falcon512_make_public"
  c_falcon512_make_public ::
    SizedPtr FalconPubKeySize ->
    SizedPtr FalconPrivKeySize ->
    SizedPtr FalconTmpMakePubSize ->
    IO CInt

-- | @c_falcon512_sign sig sk msg msgLen tmp@: deterministic padded
-- signature; see @cbits/falcon_util.c@ for how the signing randomness is
-- derived. Wipes @tmp@ before returning.
foreign import ccall safe "cardano_falcon512_sign"
  c_falcon512_sign ::
    SizedPtr FalconSigSize ->
    SizedPtr FalconPrivKeySize ->
    Ptr Word8 ->
    CSize ->
    SizedPtr FalconTmpSignSize ->
    IO CInt

-- | @c_falcon512_verify sig pk msg msgLen tmp@: 0 if the signature is valid.
foreign import ccall unsafe "cardano_falcon512_verify"
  c_falcon512_verify ::
    SizedPtr FalconSigSize ->
    SizedPtr FalconPubKeySize ->
    Ptr Word8 ->
    CSize ->
    SizedPtr FalconTmpVerifySize ->
    IO CInt

-- | @c_falcon512_check_private sk tmp@: 0 if the private key is one Falcon key
-- generation could have produced. Takes about 0.4 ms. Wipes @tmp@ before
-- returning.
foreign import ccall unsafe "cardano_falcon512_check_private"
  c_falcon512_check_private ::
    SizedPtr FalconPrivKeySize ->
    SizedPtr FalconTmpKeygenSize ->
    IO CInt
