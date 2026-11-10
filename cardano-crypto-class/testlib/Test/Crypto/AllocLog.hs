{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Crypto.AllocLog where

import Control.Monad.IO.Class (liftIO)
import Control.Tracer
import qualified Data.Foldable as F (foldl')
import Data.IORef
import Data.Set (Set)
import qualified Data.Set as Set
import Foreign.Concurrent
import Foreign.Ptr

import Cardano.Crypto.Libsodium (withMLockedForeignPtr)
import Cardano.Crypto.Libsodium.Memory (MLockedAllocator (..))
import Cardano.Crypto.Libsodium.Memory.Internal (MLockedForeignPtr (..))

-- | Allocation log event. These are emitted automatically whenever mlocked
-- memory is allocated through the 'mlockedAllocForeignPtr' primitive, or
-- released through an associated finalizer (either explicitly or due to GC).
-- Additional events that are not actual allocations/deallocations, but may
-- provide useful debugging context, can be inserted as 'MarkerEv'.
data AllocEvent
  = AllocEv !WordPtr
  | FreeEv !WordPtr
  | MarkerEv !String
  deriving (Eq, Show)

mkLoggingAllocator ::
  Tracer IO AllocEvent -> MLockedAllocator IO -> MLockedAllocator IO
mkLoggingAllocator tracer ioAllocator =
  MLockedAllocator
    { mlAllocate =
        \size -> do
          sfptr@(SFP fptr) <- mlAllocate ioAllocator size
          addr <- withMLockedForeignPtr sfptr (return . ptrToWordPtr)
          traceWith tracer (AllocEv addr)
          addForeignPtrFinalizer fptr (traceWith tracer (FreeEv addr))
          return sfptr
    }

eventTracer :: IORef [event] -> Tracer IO event
eventTracer logVar = mkTracer (\ev -> liftIO $ atomicModifyIORef' logVar (\acc -> (acc ++ [ev], ())))

matchAllocLog :: [AllocEvent] -> Set WordPtr
matchAllocLog = F.foldl' (flip go) Set.empty
  where
    go (AllocEv ptr) = Set.insert ptr
    go (FreeEv ptr) = Set.delete ptr
    go (MarkerEv _) = id
