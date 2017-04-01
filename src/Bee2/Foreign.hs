module Bee2.Foreign
  ( ErrT(..), SizeT(..), PCChar, Octet, POctet, PCOctet, PVoid, PCVoid
  , RngT, RngStateT
  
  , BS.unsafeCreate, BS.unsafeCreateUptoN
  , BS.unsafeUseAsCStringLen
  
  , Ptr, castPtr
  , unsafePerformIO

  , unsafeUseAsCStringLen'
  , unsafeCreate'
  , tryUnsafeCreate'

  , trace
  )where

import Bee2.Defs

import qualified Data.ByteString.Internal as BS
  ( unsafeCreate, unsafeCreateUptoN
  )
import qualified Data.ByteString.Unsafe as BS
  ( unsafeUseAsCStringLen
  )

import Foreign.C.Types
  ( CUInt(..), CUChar, CChar, CSize(..)
  )
import Foreign.Ptr
  ( Ptr, castPtr
  )
import Foreign.ForeignPtr
  ()
import System.IO.Unsafe
  ( unsafePerformIO
  )

import Debug.Trace
  ( trace
  )


-- types used in foreign imports

-- err_t
type ErrT = CUInt
-- size_t
type SizeT = CSize
-- char const *
type PCChar = Ptr CChar
-- octet
type Octet = CUChar
-- octet *
type POctet = Ptr Octet
-- octet const *
type PCOctet = Ptr Octet
-- void *
type PVoid = Ptr ()
-- void const *
type PCVoid = Ptr ()



-- void *
type RngStateT = Octets
-- gen_i
type RngT
  = Ptr () -- void *buf
  -> SizeT -- size_t cout
  -> Ptr () -- void *state
  -> () -- 



unsafeUseAsCStringLen'
  :: Octets
  -> (PCOctet -> SizeT -> IO a)
  -> IO a
unsafeUseAsCStringLen' bs f =
  BS.unsafeUseAsCStringLen bs $ \(p,s) -> f (castPtr p) (fromIntegral s)

unsafeCreate'
  :: Int
  -> (POctet -> IO ErrT)
  -> Octets
unsafeCreate' n f = bs where
  bs = BS.unsafeCreateUptoN n $ \p -> do
    err <- f (castPtr p)
    case err of
      0 -> return n
      _ -> error $ "unsafeCreate' error: " ++ show err

tryUnsafeCreate'
  :: ErrT
  -> Int
  -> (POctet -> IO ErrT)
  -> Maybe Octets
tryUnsafeCreate' e'nothing n f = if n == getSize bs then Just bs else Nothing where
  bs = BS.unsafeCreateUptoN n $ \p -> do
    err <- f (castPtr p)
    case err of
      0 -> return n
      _ | err == e'nothing -> return 0
        | otherwise -> error $ "tryUnsafeCreate' error: " ++ show err


