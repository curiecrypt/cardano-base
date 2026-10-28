{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}

-- | Known-answer tests for 'Falcon512DSIGN', against the NIST round 3 vectors
-- in "Test.Crypto.Vector.Falcon512Vectors".
--
-- Key generation, key derivation and verification are checked against the
-- NIST answers. Signing cannot be: NIST signs with fresh randomness, while
-- this binding derives it from the key and the message. Our signatures of the
-- NIST keys and messages are instead pinned by a digest.
module Test.Crypto.Vector.Falcon512DSIGN (
  tests,
) where

import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (..))
import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (..),
  Falcon512DSIGN,
 )
import Cardano.Crypto.Falcon.Internal (c_falcon512_keygen)
import Cardano.Crypto.Hash (SHA256, hashToStringAsHex, hashWith)
import Cardano.Crypto.PinnedSizedBytes (psbCreateSizedResult, psbToByteString)
import Cardano.Foreign (allocaSized)
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Maybe (fromJust)
import Foreign.Ptr (castPtr)
import Test.Crypto.Vector.Falcon512Vectors (Falcon512Vector (..), falcon512Vectors)
import Test.Crypto.Vector.SerializationUtils (unsafeUnHex)
import Test.Hspec (Spec, describe, it, shouldBe)

tests :: Spec
tests =
  describe "Falcon512DSIGN NIST round 3 KATs" $ do
    forM_ falcon512Vectors $ \v ->
      describe ("count = " ++ show (kvCount v)) $ do
        it "keygen from the NIST seed gives the NIST keys" $ do
          (sk, vk) <- keygenFromSeed (unsafeUnHex (kvKeygenSeed v))
          sk `shouldBe` unsafeUnHex (kvSignKey v)
          vk `shouldBe` unsafeUnHex (kvVerKey v)
        it "deriveVerKeyDSIGN gives the NIST verification key" $
          rawEncodeFixedSized (deriveVerKeyDSIGN (signKey v)) `shouldBe` unsafeUnHex (kvVerKey v)
        it "verifyDSIGN accepts the NIST signature" $
          verifyDSIGN () (verKey v) (message v) (sig v) `shouldBe` Right ()
    it "our signatures of the NIST keys and messages match the pinned digest" $
      hashToStringAsHex (hashWith @SHA256 id ownSigs) `shouldBe` ownSigsDigest
  where
    ownSigs =
      BS.concat
        [rawEncodeFixedSized (signDSIGN () (message v) (signKey v)) | v <- falcon512Vectors]

-- | SHA256 of our padded signatures of the vectors' keys and messages, in
-- order. Computed with @kat_convert@, whose signatures NIST's
-- @crypto_sign_open@ accepts. A change here means signing changed.
ownSigsDigest :: String
ownSigsDigest = "d492f68465fbe2ec4ae3958cf05584b87ed6075d11703d99f806dc2a49174315"

message :: Falcon512Vector -> ByteString
message = unsafeUnHex . kvMessage

signKey :: Falcon512Vector -> SignKeyDSIGN Falcon512DSIGN
signKey = fromJust . rawDecodeFixedSized . unsafeUnHex . kvSignKey

verKey :: Falcon512Vector -> VerKeyDSIGN Falcon512DSIGN
verKey = fromJust . rawDecodeFixedSized . unsafeUnHex . kvVerKey

sig :: Falcon512Vector -> SigDSIGN Falcon512DSIGN
sig = fromJust . rawDecodeFixedSized . unsafeUnHex . kvSig

-- | Key generation from a seed of any length. NIST seeds are 48 bytes, while
-- 'genKeyDSIGN' takes 32, so this calls the C helper directly, as
-- 'genKeyDSIGN' does.
keygenFromSeed :: ByteString -> IO (ByteString, ByteString)
keygenFromSeed seed =
  unsafeUseAsCStringLen seed $ \(seedPtr, seedLen) ->
    allocaSized $ \tmpPtr -> do
      (sk, (vk, rc)) <-
        psbCreateSizedResult $ \skPtr ->
          psbCreateSizedResult $ \vkPtr ->
            c_falcon512_keygen (castPtr seedPtr) (fromIntegral seedLen) skPtr vkPtr tmpPtr
      rc `shouldBe` 0
      pure (psbToByteString sk, psbToByteString vk)
