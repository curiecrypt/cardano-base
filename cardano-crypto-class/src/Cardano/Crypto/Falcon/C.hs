{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}

-- | Raw FFI bindings to the Falcon-det512 helpers in @cbits/falcon_util.c@,
-- which wrap the vendored deterministic Falcon implementation in
-- @cbits/falcon@ (algorand/falcon).
--
-- The buffer sizes in the types come from @cbits/falcon_util.h@, whose values
-- are checked against the vendored code with @static_assert@ at compile time.
-- Every function returns @CARDANO_FALCON_SUCCESS@ (0) on success, or a
-- negative @CARDANO_FALCON_ERR_*@ code.
module Cardano.Crypto.Falcon.C (
  c_cardano_falcon_det512_keygen,
  c_cardano_falcon_det512_derive_pubkey,
  c_cardano_falcon_det512_sign,
  c_cardano_falcon_det512_verify,
) where

#include "falcon_util.h"

import Cardano.Foreign (SizedPtr (SizedPtr))
import Foreign.C.Types (CChar, CInt (CInt), CSize (CSize))
import Foreign.Ptr (Ptr)

-- | Generate a key pair from a seed of any length. The same seed always gives
-- the same key pair.
foreign import ccall "cardano_falcon_det512_keygen"
  c_cardano_falcon_det512_keygen ::
    Ptr CChar -> -- seed
    CSize -> -- seed length in bytes
    SizedPtr CARDANO_FALCON_DET512_PRIVKEY_SIZE -> -- out: private key
    SizedPtr CARDANO_FALCON_DET512_PUBKEY_SIZE -> -- out: public key
    IO CInt

-- | Recompute the public key of a private key.
foreign import ccall "cardano_falcon_det512_derive_pubkey"
  c_cardano_falcon_det512_derive_pubkey ::
    SizedPtr CARDANO_FALCON_DET512_PRIVKEY_SIZE -> -- private key
    SizedPtr CARDANO_FALCON_DET512_PUBKEY_SIZE -> -- out: public key
    IO CInt

-- | Sign a message deterministically, producing a CT-format signature.
foreign import ccall "cardano_falcon_det512_sign"
  c_cardano_falcon_det512_sign ::
    SizedPtr CARDANO_FALCON_DET512_PRIVKEY_SIZE -> -- private key
    Ptr CChar -> -- message
    CSize -> -- message length in bytes
    SizedPtr CARDANO_FALCON_DET512_SIG_SIZE -> -- out: signature
    IO CInt

-- | Verify a CT-format signature.
foreign import ccall "cardano_falcon_det512_verify"
  c_cardano_falcon_det512_verify ::
    SizedPtr CARDANO_FALCON_DET512_SIG_SIZE -> -- signature
    SizedPtr CARDANO_FALCON_DET512_PUBKEY_SIZE -> -- public key
    Ptr CChar -> -- message
    CSize -> -- message length in bytes
    IO CInt
