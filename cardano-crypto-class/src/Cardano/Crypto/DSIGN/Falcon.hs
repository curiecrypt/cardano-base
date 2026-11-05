{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
-- According to the documentation for unsafePerformIO:
--
-- > Make sure that the either you switch off let-floating
-- > (-fno-full-laziness), or that the call to unsafePerformIO cannot float
-- > outside a lambda.
--
-- If we do not switch off let-floating, our calls to unsafeDupablePerformIO for
-- FFI functions become nondeterministic in their behaviour when run with
-- parallelism enabled (such as -with-rtsopts=-N), possibly yielding wrong
-- answers on a range of tasks, including serialization.
{-# OPTIONS_GHC -fno-full-laziness #-}

-- | Deterministic Falcon-512 digital signatures.
module Cardano.Crypto.DSIGN.Falcon (
  FalconDet512DSIGN,
  VerKeyDSIGN,
  SignKeyDSIGN,
  SigDSIGN,
) where

#include "falcon_util.h"

import Cardano.Binary (FromCBOR (fromCBOR), ToCBOR (encodedSizeExpr, toCBOR))
import Cardano.Binary.FixedSizeCodec (
  FixedSizeCodec (..),
  decodeFixedSized,
  encodeFixedSized,
  guardFixedSized,
 )
import Cardano.Crypto.DSIGN.Class (
  DSIGNAlgorithm (
    SeedSizeDSIGN,
    SigDSIGN,
    SignKeyDSIGN,
    Signable,
    VerKeyDSIGN,
    algorithmNameDSIGN,
    deriveVerKeyDSIGN,
    genKeyDSIGN,
    signDSIGN,
    verifyDSIGN
  ),
  DSIGNMAlgorithm (
    SignKeyDSIGNM,
    cloneKeyDSIGNMWith,
    deriveVerKeyDSIGNM,
    forgetSignKeyDSIGNMWith,
    genKeyDSIGNMWith,
    getSeedDSIGNMWith,
    signDSIGNM
  ),
  encodedSigDSIGNSizeExpr,
  encodedSignKeyDSIGNSizeExpr,
  encodedVerKeyDSIGNSizeExpr,
  seedSizeDSIGN,
 )
import Cardano.Crypto.Falcon.C (
  c_cardano_falcon_det512_derive_pubkey,
  c_cardano_falcon_det512_keygen,
  c_cardano_falcon_det512_sign,
  c_cardano_falcon_det512_verify,
 )
import Cardano.Crypto.Libsodium (
  MLockedSizedBytes,
  mlsbCopyWith,
  mlsbFinalize,
  mlsbNewWith,
  mlsbUseAsCPtr,
  mlsbUseAsSizedPtr,
 )
import Cardano.Crypto.Libsodium.C (c_sodium_compare)
import Cardano.Crypto.Libsodium.MLockedSeed (mlockedSeedNewWith, mlockedSeedUseAsCPtr)
import Cardano.Crypto.PinnedSizedBytes (
  PinnedSizedBytes,
  psbCreateSizedResult,
  psbToByteString,
  psbUseAsCPtr,
  psbUseAsSizedPtr,
 )
import Cardano.Crypto.Seed (getBytesFromSeedT, mkSeedFromBytes)
import Cardano.Crypto.Util (SignableRepresentation (getSignableRepresentation))
import Cardano.Foreign (SizedPtr (SizedPtr), allocaSized)
import Control.DeepSeq (NFData (rnf), rwhnf)
import Control.Monad (when, (<$!>))
import Control.Monad.Class.MonadST (MonadST (stToIO))
import Control.Monad.Class.MonadThrow (MonadThrow, throwIO)
import Control.Monad.ST.Unsafe (unsafeIOToST)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Proxy (Proxy (Proxy))
import Foreign.C.Types (CInt, CSize)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (castPtr, plusPtr)
import GHC.Generics (Generic)
import GHC.TypeLits (type (+))
import NoThunks.Class (NoThunks)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Falcon-512 in the deterministic mode of algorand/falcon, a post-quantum
-- signature scheme over NTRU lattices (NIST security level 1).
--
-- * Signing is deterministic: a given key and message always give the same
--   signature.
--
-- * Signatures use the fixed-size CT format (770 bytes). The deterministic
--   specification signs in the compressed format only, so the compressed
--   signature is converted to CT, a lossless re-encoding of the same
--   signature.
--
-- * Verification keys are 897 bytes and seeds 32 bytes. A signing key holds
--   its seed followed by the encoded private key (1281 bytes), and is
--   serialised as its seed only, as for Ed25519: deserialising runs key
--   generation.
--
-- * Signatures are not interoperable with standard (salted) Falcon-512: the
--   deterministic mode uses a fixed, versioned salt and its own header byte.
--
-- * As for Ed25519, decoding a verification key or a signature only checks
--   the length. Verification rejects a malformed one.
data FalconDet512DSIGN

-- | Size of a signing key in memory: the seed followed by the encoded private
-- key.
type SeedAndPrivKeySize = CARDANO_FALCON_DET512_SEED_SIZE + CARDANO_FALCON_DET512_PRIVKEY_SIZE

-- | The encoded private key inside a signing key, after the seed.
privKeyPtr :: SizedPtr SeedAndPrivKeySize -> SizedPtr CARDANO_FALCON_DET512_PRIVKEY_SIZE
privKeyPtr (SizedPtr p) = SizedPtr (p `plusPtr` CARDANO_FALCON_DET512_SEED_SIZE)

instance DSIGNAlgorithm FalconDet512DSIGN where
  type SeedSizeDSIGN FalconDet512DSIGN = CARDANO_FALCON_DET512_SEED_SIZE
  type Signable FalconDet512DSIGN = SignableRepresentation

  newtype VerKeyDSIGN FalconDet512DSIGN
    = VerKeyFalconDet512 (PinnedSizedBytes CARDANO_FALCON_DET512_PUBKEY_SIZE)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  newtype SignKeyDSIGN FalconDet512DSIGN
    = SignKeyFalconDet512 (PinnedSizedBytes SeedAndPrivKeySize)
    deriving newtype (NFData)
    deriving stock (Generic)
    deriving anyclass (NoThunks)

  newtype SigDSIGN FalconDet512DSIGN
    = SigFalconDet512 (PinnedSizedBytes CARDANO_FALCON_DET512_SIG_SIZE)
    deriving newtype (Eq, NFData)
    deriving stock (Show, Generic)
    deriving anyclass (NoThunks)

  algorithmNameDSIGN _ = "falcon-det512"

  {-# NOINLINE deriveVerKeyDSIGN #-}
  deriveVerKeyDSIGN (SignKeyFalconDet512 skPsb) =
    VerKeyFalconDet512 . unsafeDupablePerformIO $ do
      (vkPsb, rc) <- psbCreateSizedResult $ \vkp ->
        psbUseAsSizedPtr skPsb $ \skp ->
          c_cardano_falcon_det512_derive_pubkey (privKeyPtr skp) vkp
      checkSuccess "deriveVerKeyDSIGN" rc
      pure vkPsb

  {-# NOINLINE signDSIGN #-}
  signDSIGN () msg (SignKeyFalconDet512 skPsb) =
    SigFalconDet512 . unsafeDupablePerformIO $ do
      (sigPsb, rc) <- psbCreateSizedResult $ \sigp ->
        psbUseAsSizedPtr skPsb $ \skp ->
          unsafeUseAsCStringLen (getSignableRepresentation msg) $ \(msgp, msgLen) ->
            c_cardano_falcon_det512_sign (privKeyPtr skp) msgp (fromIntegral @Int @CSize msgLen) sigp
      checkSuccess "signDSIGN" rc
      pure sigPsb

  {-# NOINLINE verifyDSIGN #-}
  verifyDSIGN () (VerKeyFalconDet512 vkPsb) msg (SigFalconDet512 sigPsb) =
    unsafeDupablePerformIO $ do
      rc <- psbUseAsSizedPtr sigPsb $ \sigp ->
        psbUseAsSizedPtr vkPsb $ \vkp ->
          unsafeUseAsCStringLen (getSignableRepresentation msg) $ \(msgp, msgLen) ->
            c_cardano_falcon_det512_verify sigp vkp msgp (fromIntegral @Int @CSize msgLen)
      pure $
        if rc == CARDANO_FALCON_SUCCESS
          then Right ()
          else Left "verifyDSIGN: FalconDet512DSIGN signature failed to verify"

  {-# NOINLINE genKeyDSIGN #-}
  genKeyDSIGN seed =
    SignKeyFalconDet512 . unsafeDupablePerformIO $ do
      let (seedBytes, _) = getBytesFromSeedT (seedSizeDSIGN (Proxy @FalconDet512DSIGN)) seed
      (skPsb, rc) <- psbCreateSizedResult $ \skp@(SizedPtr skPtr) ->
        -- The verification key is recomputed by 'deriveVerKeyDSIGN' when needed.
        allocaSized $ \vkp ->
          unsafeUseAsCStringLen seedBytes $ \(seedp, seedLen) -> do
            copyBytes (castPtr skPtr) seedp seedLen
            c_cardano_falcon_det512_keygen seedp (fromIntegral @Int @CSize seedLen) (privKeyPtr skp) vkp
      checkSuccess "genKeyDSIGN" rc
      pure skPsb

-- Key generation, key derivation and signing cannot fail on valid inputs, so a
-- failure is an error, as for Schnorr.
checkSuccess :: String -> CInt -> IO ()
checkSuccess fn rc =
  when (rc /= CARDANO_FALCON_SUCCESS) $
    error (fn <> ": FalconDet512DSIGN failed with code " <> show rc)

instance Show (SignKeyDSIGN FalconDet512DSIGN) where
  show _ = "FalconDet512DSIGN:<secret>"

-- Constant-time equality for signing keys
instance Eq (SignKeyDSIGN FalconDet512DSIGN) where
  {-# NOINLINE (==) #-}
  SignKeyFalconDet512 sk1Psb == SignKeyFalconDet512 sk2Psb =
    unsafeDupablePerformIO $
      psbUseAsCPtr sk1Psb $ \sk1Ptr ->
        psbUseAsCPtr sk2Psb $ \sk2Ptr -> do
          res <- c_sodium_compare sk1Ptr sk2Ptr size
          pure (res == 0)
    where
      size = fromIntegral @Int @CSize (CARDANO_FALCON_DET512_SEED_SIZE + CARDANO_FALCON_DET512_PRIVKEY_SIZE)

instance FixedSizeCodec (VerKeyDSIGN FalconDet512DSIGN) where
  type FixedSize (VerKeyDSIGN FalconDet512DSIGN) = CARDANO_FALCON_DET512_PUBKEY_SIZE
  rawEncodeFixedSized (VerKeyFalconDet512 vkPsb) = psbToByteString vkPsb
  rawDecodeFixedSized bs = VerKeyFalconDet512 <$> rawDecodeFixedSized bs

-- As for Ed25519, a signing key is serialised as its seed, and deserialising
-- runs key generation.
instance FixedSizeCodec (SignKeyDSIGN FalconDet512DSIGN) where
  type FixedSize (SignKeyDSIGN FalconDet512DSIGN) = CARDANO_FALCON_DET512_SEED_SIZE
  rawEncodeFixedSized (SignKeyFalconDet512 skPsb) =
    unsafeDupablePerformIO . psbUseAsCPtr skPsb $ \skPtr ->
      BS.packCStringLen (castPtr skPtr, CARDANO_FALCON_DET512_SEED_SIZE)
  rawDecodeFixedSized bs = guardFixedSized bs $ pure . genKeyDSIGN $ mkSeedFromBytes bs

instance FixedSizeCodec (SigDSIGN FalconDet512DSIGN) where
  type FixedSize (SigDSIGN FalconDet512DSIGN) = CARDANO_FALCON_DET512_SIG_SIZE
  rawEncodeFixedSized (SigFalconDet512 sigPsb) = psbToByteString sigPsb
  rawDecodeFixedSized bs = SigFalconDet512 <$> rawDecodeFixedSized bs

instance ToCBOR (VerKeyDSIGN FalconDet512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedVerKeyDSIGNSizeExpr

instance FromCBOR (VerKeyDSIGN FalconDet512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SignKeyDSIGN FalconDet512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSignKeyDSIGNSizeExpr

instance FromCBOR (SignKeyDSIGN FalconDet512DSIGN) where
  fromCBOR = decodeFixedSized

instance ToCBOR (SigDSIGN FalconDet512DSIGN) where
  toCBOR = encodeFixedSized
  encodedSizeExpr _ = encodedSigDSIGNSizeExpr

instance FromCBOR (SigDSIGN FalconDet512DSIGN) where
  fromCBOR = decodeFixedSized

--
-- Mlocked signing keys
--

-- As for Ed25519, 'NoThunks' and 'NFData' only look at the mlocked bytes.
deriving via
  (MLockedSizedBytes SeedAndPrivKeySize)
  instance
    NoThunks (SignKeyDSIGNM FalconDet512DSIGN)

instance NFData (SignKeyDSIGNM FalconDet512DSIGN) where
  rnf = rwhnf

-- As 'checkSuccess', for the mlocked methods: they throw through 'MonadThrow',
-- as Ed25519's do.
throwOnFailure :: MonadThrow m => String -> CInt -> m ()
throwOnFailure fn rc =
  when (rc /= CARDANO_FALCON_SUCCESS) $
    throwIO . userError $
      fn <> ": FalconDet512DSIGN failed with code " <> show rc

-- The same layout as 'SignKeyDSIGN' (the seed followed by the encoded private
-- key), in mlocked memory. As for Ed25519, failures throw an exception.
instance DSIGNMAlgorithm FalconDet512DSIGN where
  newtype SignKeyDSIGNM FalconDet512DSIGN
    = SignKeyFalconDet512M (MLockedSizedBytes SeedAndPrivKeySize)
    deriving (Show)

  deriveVerKeyDSIGNM (SignKeyFalconDet512M sk) = do
    (vkPsb, rc) <- mlsbUseAsSizedPtr sk $ \skp ->
      stToIO . unsafeIOToST . psbCreateSizedResult $ \vkp ->
        c_cardano_falcon_det512_derive_pubkey (privKeyPtr skp) vkp
    throwOnFailure "deriveVerKeyDSIGNM" rc
    pure $! VerKeyFalconDet512 vkPsb

  signDSIGNM () msg (SignKeyFalconDet512M sk) = do
    (sigPsb, rc) <- mlsbUseAsSizedPtr sk $ \skp ->
      stToIO . unsafeIOToST . psbCreateSizedResult $ \sigp ->
        unsafeUseAsCStringLen (getSignableRepresentation msg) $ \(msgp, msgLen) ->
          c_cardano_falcon_det512_sign (privKeyPtr skp) msgp (fromIntegral @Int @CSize msgLen) sigp
    throwOnFailure "signDSIGNM" rc
    pure $! SigFalconDet512 sigPsb

  {-# NOINLINE genKeyDSIGNMWith #-}
  genKeyDSIGNMWith allocator seed = do
    sk <- mlsbNewWith allocator
    rc <- mlsbUseAsSizedPtr sk $ \skp@(SizedPtr skPtr) ->
      mlockedSeedUseAsCPtr seed $ \seedPtr ->
        stToIO . unsafeIOToST $ do
          copyBytes (castPtr skPtr) seedPtr CARDANO_FALCON_DET512_SEED_SIZE
          -- The verification key is recomputed by 'deriveVerKeyDSIGNM' when needed.
          allocaSized $ \vkp ->
            c_cardano_falcon_det512_keygen
              (castPtr seedPtr)
              CARDANO_FALCON_DET512_SEED_SIZE
              (privKeyPtr skp)
              vkp
    throwOnFailure "genKeyDSIGNM" rc
    pure $! SignKeyFalconDet512M sk

  cloneKeyDSIGNMWith allocator (SignKeyFalconDet512M sk) =
    SignKeyFalconDet512M <$!> mlsbCopyWith allocator sk

  getSeedDSIGNMWith allocator _ (SignKeyFalconDet512M sk) = do
    seed <- mlockedSeedNewWith allocator
    mlsbUseAsCPtr sk $ \skPtr ->
      mlockedSeedUseAsCPtr seed $ \seedPtr ->
        stToIO . unsafeIOToST $ copyBytes seedPtr skPtr CARDANO_FALCON_DET512_SEED_SIZE
    pure seed

  forgetSignKeyDSIGNMWith _ (SignKeyFalconDet512M sk) = mlsbFinalize sk
