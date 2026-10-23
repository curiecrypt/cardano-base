{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
-- See the note on -fno-full-laziness in "Cardano.Crypto.DSIGN.Ed25519": the
-- FFI calls below run under unsafeDupablePerformIO and must not float out of
-- their lambdas.
{-# OPTIONS_GHC -fno-full-laziness #-}

-- | Falcon-512 digital signatures (Falcon round 3, padded format).
--
-- Backed by the Falcon round 3 reference implementation in @cbits/falcon@,
-- through the helpers in @cbits/falcon_util.c@ ("Cardano.Crypto.Falcon.Internal").
--
-- * Signatures are in Falcon's fixed-size padded format (666 bytes), so any
--   Falcon-512 verifier accepts them.
-- * Signing is deterministic: the same key and message always give the same
--   signature. The signing randomness is derived from the key and the message
--   in @cbits/falcon_util.c@; this derandomization is a choice of this binding,
--   not part of the Falcon specification.
-- * Decoding checks the length and the one-byte Falcon header of keys and
--   signatures. Deeper validity (coefficient ranges, key consistency) is checked
--   when a key or signature is used.
module Cardano.Crypto.DSIGN.Falcon (
  Falcon512DSIGN,
  SigDSIGN (..),
  SignKeyDSIGN (..),
  VerKeyDSIGN (..),
)
where

import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
 )
import Control.DeepSeq (NFData)
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Foreign.C.Types (CInt, CSize)
import Foreign.Ptr (castPtr)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Cardano.Binary (FromCBOR (..), ToCBOR (..))

import Cardano.Crypto.DSIGN.Class
import Cardano.Crypto.Falcon.Internal
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreateSized,
  psbToByteString,
  psbUseAsSizedPtr,
 )
import Cardano.Crypto.Seed
import Cardano.Crypto.Util (SignableRepresentation (..))
import Cardano.Foreign (allocaSized)

data Falcon512DSIGN

instance NoThunks (VerKeyDSIGN Falcon512DSIGN)
instance NoThunks (SignKeyDSIGN Falcon512DSIGN)
instance NoThunks (SigDSIGN Falcon512DSIGN)

-- | Throw if a Falcon helper returned a nonzero (FALCON_ERR_*) code.
throwOnFalconError :: String -> CInt -> IO ()
throwOnFalconError context res =
  unless (res == 0) $
    ioError (userError (context ++ ": Falcon error " ++ show res))

instance DSIGNAlgorithm Falcon512DSIGN where
  -- \| 256 bits of seed, the input to Falcon's SHAKE256-based key generation.
  type SeedSizeDSIGN Falcon512DSIGN = 32

  --
  -- Key and signature types
  --

  newtype VerKeyDSIGN Falcon512DSIGN = VerKeyFalcon512DSIGN (PinnedSizedBytes FalconPubKeySize)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  -- Show is hidden below; the signing key must not end up in logs.
  newtype SignKeyDSIGN Falcon512DSIGN = SignKeyFalcon512DSIGN (PinnedSizedBytes FalconPrivKeySize)
    deriving (Eq, Generic)
    deriving newtype (NFData)

  newtype SigDSIGN Falcon512DSIGN = SigFalcon512DSIGN (PinnedSizedBytes FalconSigSize)
    deriving (Show, Eq, Generic)
    deriving newtype (NFData)

  --
  -- Metadata and basic key operations
  --

  algorithmNameDSIGN _ = "falcon-512"

  deriveVerKeyDSIGN (SignKeyFalcon512DSIGN sk) =
    VerKeyFalcon512DSIGN $
      unsafeDupablePerformIO $
        psbUseAsSizedPtr sk $ \skPtr ->
          psbCreateSized $ \pkPtr ->
            allocaSized $ \tmpPtr ->
              throwOnFalconError "deriveVerKeyDSIGN @Falcon512DSIGN"
                =<< c_falcon512_make_public pkPtr skPtr tmpPtr

  --
  -- Core algorithm operations
  --

  type Signable Falcon512DSIGN = SignableRepresentation

  signDSIGN () a (SignKeyFalcon512DSIGN sk) =
    let bs = getSignableRepresentation a
     in SigFalcon512DSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen bs $ \(msgPtr, msgLen) ->
              psbUseAsSizedPtr sk $ \skPtr ->
                psbCreateSized $ \sigPtr ->
                  allocaSized $ \tmpPtr ->
                    throwOnFalconError "signDSIGN @Falcon512DSIGN"
                      =<< c_falcon512_sign
                        sigPtr
                        skPtr
                        (castPtr msgPtr)
                        (fromIntegral @Int @CSize msgLen)
                        tmpPtr

  verifyDSIGN () (VerKeyFalcon512DSIGN vk) a (SigFalcon512DSIGN sig) =
    let bs = getSignableRepresentation a
     in unsafeDupablePerformIO $
          BS.useAsCStringLen bs $ \(msgPtr, msgLen) ->
            psbUseAsSizedPtr vk $ \vkPtr ->
              psbUseAsSizedPtr sig $ \sigPtr ->
                allocaSized $ \tmpPtr -> do
                  res <-
                    c_falcon512_verify
                      sigPtr
                      vkPtr
                      (castPtr msgPtr)
                      (fromIntegral @Int @CSize msgLen)
                      tmpPtr
                  pure $
                    if res == 0
                      then Right ()
                      else Left ("Verification failed: Falcon error " ++ show res)

  --
  -- Key generation
  --

  genKeyDSIGN seed =
    let (sb, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @Falcon512DSIGN)) seed
     in SignKeyFalcon512DSIGN $
          unsafeDupablePerformIO $
            BS.useAsCStringLen sb $ \(seedPtr, seedLen) ->
              psbCreateSized $ \skPtr ->
                allocaSized $ \pkPtr ->
                  allocaSized $ \tmpPtr ->
                    throwOnFalconError "genKeyDSIGN @Falcon512DSIGN"
                      =<< c_falcon512_keygen
                        (castPtr seedPtr)
                        (fromIntegral @Int @CSize seedLen)
                        skPtr
                        pkPtr
                        tmpPtr

instance Show (SignKeyDSIGN Falcon512DSIGN) where
  show _ = "Falcon512DSIGN:<secret>"

--
-- Encoding
--

-- | First byte of each encoded Falcon-512 object, as written by the vendored
-- code (cbits/falcon/falcon.c): 0x00 + logn for public keys, 0x50 + logn for
-- private keys, 0x30 + logn for padded signatures, with logn = 9.
pubKeyHeader, privKeyHeader, sigHeader :: Word8
pubKeyHeader = 0x09
privKeyHeader = 0x59
sigHeader = 0x39

-- | Fails unless the encoding starts with the expected header byte.
checkHeader :: MonadFail m => Word8 -> BS.ByteString -> m ()
checkHeader header bs =
  unless (BS.take 1 bs == BS.singleton header) $
    fail ("Falcon512DSIGN: bad header byte, expected " ++ show header)

instance FixedSizeCodec (VerKeyDSIGN Falcon512DSIGN) where
  type FixedSize (VerKeyDSIGN Falcon512DSIGN) = FalconPubKeySize
  rawEncodeFixedSized (VerKeyFalcon512DSIGN vk) = psbToByteString vk
  rawDecodeFixedSized bs =
    checkHeader pubKeyHeader bs *> (VerKeyFalcon512DSIGN <$> rawDecodeFixedSized bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SignKeyDSIGN Falcon512DSIGN) where
  type FixedSize (SignKeyDSIGN Falcon512DSIGN) = FalconPrivKeySize
  rawEncodeFixedSized (SignKeyFalcon512DSIGN sk) = psbToByteString sk
  rawDecodeFixedSized bs =
    checkHeader privKeyHeader bs *> (SignKeyFalcon512DSIGN <$> rawDecodeFixedSized bs)
  {-# INLINE rawDecodeFixedSized #-}

instance FixedSizeCodec (SigDSIGN Falcon512DSIGN) where
  type FixedSize (SigDSIGN Falcon512DSIGN) = FalconSigSize
  rawEncodeFixedSized (SigFalcon512DSIGN sig) = psbToByteString sig
  rawDecodeFixedSized bs =
    checkHeader sigHeader bs *> (SigFalcon512DSIGN <$> rawDecodeFixedSized bs)
  {-# INLINE rawDecodeFixedSized #-}

instance ToCBOR (VerKeyDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN Falcon512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN Falcon512DSIGN) where
  fromCBOR = decodeFixedSized
