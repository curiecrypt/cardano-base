{-# LANGUAGE DataKinds #-}

-- | Known-answer tests for 'FalconDet512DSIGN': the CT test vectors of
-- algorand/falcon, described in @falcon-det512-test-vectors/README.md@.
module Test.Crypto.Vector.FalconDSIGN (
  tests,
)
where

import Cardano.Binary.FixedSizeCodec (FixedSizeCodec (rawDecodeFixedSized))
import Cardano.Crypto.DSIGN (
  DSIGNAlgorithm (SigDSIGN, VerKeyDSIGN, verifyDSIGN),
  FalconDet512DSIGN,
 )
import Cardano.Crypto.Falcon.C (c_cardano_falcon_det512_keygen, c_cardano_falcon_det512_sign)
import Cardano.Crypto.PinnedSizedBytes (
  psbCreateSizedResult,
  psbFromByteStringM,
  psbToByteString,
  psbUseAsSizedPtr,
 )
import Control.Monad (forM, forM_)
import Crypto.Hash (SHAKE256 (SHAKE256), hashWith)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Paths_cardano_crypto_class (getDataFileName)
import Test.Crypto.Vector.SerializationUtils (unsafeUnHex)
import Test.HUnit (assertEqual)
import Test.Hspec (Spec, describe, it)
import Text.Printf (printf)

tests :: Spec
tests =
  describe "FalconDet512DSIGN Algorand test vectors" $ do
    it "the signing helper reproduces Algorand's CT signatures" $ do
      vectors <- loadVectors
      forM_ vectors $ \(i, sk, _, msg, sig) -> do
        sig' <- algorandSign sk msg
        assertEqual ("vector " <> show i) sig sig'
    it "verifyDSIGN accepts Algorand's CT signatures" $ do
      vectors <- loadVectors
      forM_ vectors $ \(i, _, vk, msg, sig) ->
        assertEqual ("vector " <> show i) (Right ()) (verifyDSIGN () vk msg sig)

-- | The 32 vectors, one signature per line: line @i@ is the signature of
-- 'algorandMessage' @i@ with the key pair 'algorandKeyPair' @i@.
loadVectors ::
  IO [(Int, ByteString, VerKeyDSIGN FalconDet512DSIGN, ByteString, SigDSIGN FalconDet512DSIGN)]
loadVectors = do
  path <- getDataFileName "falcon-det512-test-vectors/test_vectors/kat_ct"
  sigs <- mapM (rawDecodeFixedSized . unsafeUnHex) . BS8.lines =<< BS.readFile path
  assertEqual "number of vectors" 32 (length sigs)
  forM (zip [0 ..] sigs) $ \(i, sig) -> do
    (sk, vk) <- algorandKeyPair i
    pure (i, sk, vk, algorandMessage i, sig)

-- | The key pair of vector @i@ (raw private key, verification key), which
-- Algorand generates from the 8-byte seed @key-%04d@. 'genKeyDSIGN' takes a
-- 32-byte seed, so this calls the key generation helper directly.
algorandKeyPair :: Int -> IO (ByteString, VerKeyDSIGN FalconDet512DSIGN)
algorandKeyPair i = do
  let seed = BS8.pack (printf "key-%04d" i)
  (skPsb, (vkPsb, rc)) <- psbCreateSizedResult $ \skp ->
    psbCreateSizedResult $ \vkp ->
      unsafeUseAsCStringLen seed $ \(seedp, seedLen) ->
        c_cardano_falcon_det512_keygen seedp (fromIntegral seedLen) skp vkp
  assertEqual ("key generation for vector " <> show i) 0 rc
  vk <- rawDecodeFixedSized (psbToByteString vkPsb)
  pure (psbToByteString skPsb, vk)

-- | Sign with the signing helper that 'signDSIGN' wraps, so that the test does
-- not depend on how a 'SignKeyDSIGN' is serialised.
algorandSign :: ByteString -> ByteString -> IO (SigDSIGN FalconDet512DSIGN)
algorandSign sk msg = do
  skPsb <- psbFromByteStringM sk
  (sigPsb, rc) <- psbCreateSizedResult $ \sigp ->
    psbUseAsSizedPtr skPsb $ \skp ->
      unsafeUseAsCStringLen msg $ \(msgp, msgLen) ->
        c_cardano_falcon_det512_sign skp msgp (fromIntegral msgLen) sigp
  assertEqual "signing" 0 rc
  rawDecodeFixedSized (psbToByteString sigPsb)

-- | The message of vector @i@: the first @i@ bytes of SHAKE256 of @msg-%04d@
-- (@i < 32@, and a shorter SHAKE256 output is a prefix of a longer one).
algorandMessage :: Int -> ByteString
algorandMessage i =
  BS.take i . BA.convert $ hashWith (SHAKE256 :: SHAKE256 256) (BS8.pack (printf "msg-%04d" i))
