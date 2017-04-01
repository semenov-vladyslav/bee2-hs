module Bee2.Crypto.Bign
  ( PrivKey, PubKey, HashValue, HashOid, SigValue
  , bignSign2'bs, bignVerify'bs
  ) where

import Bee2.Defs
import Bee2.Foreign

import Data.Word
  ( Word(..)
  )
import Foreign.C.Types
  ( CUInt(..), CSize(..)
  )
import Foreign.Ptr
  ( FunPtr, nullPtr, castPtr
  )
import Foreign.C.String
  ( withCString
  )
import System.IO.Unsafe
  ( unsafePerformIO
  )

-- bign_params is defined as a struct, but we don't need to directly access it's fields
-- so this type stays abstract
-- size: 4+64+64+64+64+64+8
bignKeep = 4+64+64+64+64+64+8
type PBignParams = Ptr () -- void * -> bign_param *

foreign import ccall "bignStdParams"
  bignStdParams'cptr
    :: PBignParams -- bign_params *params
    -> PCChar -- char const *name
    -> ErrT -- err

foreign import ccall "bignGenKeypair"
  bignGenKeypair'cptr
    :: PCOctet -- privkey
    -> POctet -- pubkey
    -> PBignParams -- params
    -> FunPtr RngT -- rng
    -> ErrT -- err

foreign import ccall "bignSign"
  bignSign'cptr
    :: POctet -- sig
    -> PBignParams -- params
    -> PCOctet -- oid_der
    -> SizeT -- oid_len
    -> PCOctet -- hash
    -> PCOctet -- privkey
    -> FunPtr RngT -- rng
    -> Ptr () -- rng_state
    -> ErrT -- err

foreign import ccall "bignSign2"
  bignSign2'cptr
    :: PCOctet -- sig
    -> PBignParams -- params
    -> PCOctet -- oid_der
    -> SizeT -- oid_len
    -> PCOctet -- hash
    -> PCOctet -- privkey
    -> PCVoid -- void const *t
    -> SizeT -- t_len
    -> ErrT -- err

foreign import ccall "bignVerify"
  bignVerify'cptr
    :: PBignParams -- params
    -> PCOctet -- oid_der
    -> SizeT -- oid_len
    -> PCOctet -- hash
    -> PCOctet -- sig
    -> PCOctet -- pubkey
    -> ErrT -- err



bignStd128Oid = "1.2.112.0.2.0.34.101.45.3.1"
bignStd192Oid = "1.2.112.0.2.0.34.101.45.3.2"
bignStd256Oid = "1.2.112.0.2.0.34.101.45.3.3"

type BignParams = Octets
bignStdParams :: String -> BignParams
bignStdParams oid =
  unsafeCreate' bignKeep $ \pparams ->
  withCString oid $ \poid ->
  return $! bignStdParams'cptr (castPtr pparams) poid

bignStd128 :: BignParams
bignStd128 = bignStdParams bignStd128Oid
bignStd192 :: BignParams
bignStd192 = bignStdParams bignStd192Oid
bignStd256 :: BignParams
bignStd256 = bignStdParams bignStd256Oid

bignStd :: Word -> BignParams
bignStd 128 = bignStd128
bignStd 192 = bignStd192
bignStd 256 = bignStd256
bignStd _ = error "bignStd invalid l (must be [128,192,256])"

type PrivKey = Octets
type PubKey = Octets
type HashValue = Octets
type HashOid = Octets
type SigValue = Octets

bignSign2'bs :: Word -> PrivKey -> HashOid -> HashValue -> SigValue
bignSign2'bs l priv oid hash
  | l /= 128 && l /= 192 && l /= 256 = error "bignSign2 invalid l (must be [128,192,256]"
  | getSize priv /= fromIntegral (l `div` 4) = error "bignSign2 invalid priv size (must be [32,48,64])"
  | getSize hash /= fromIntegral (l `div` 4) = error "bignSign2 invalid hash size (must be [32,48,64])"
  | otherwise =
      unsafeCreate' (fromIntegral (3 * l `div` 8)) $ \psig ->
      unsafeUseAsCStringLen' (bignStd l) $ \pparams sparams ->
      unsafeUseAsCStringLen' priv $ \ppriv spriv ->
      unsafeUseAsCStringLen' oid $ \poid soid ->
      unsafeUseAsCStringLen' hash $ \phash shash ->
      return $! bignSign2'cptr psig (castPtr pparams) poid (fromIntegral soid) phash ppriv nullPtr 0

bignVerify'bs :: Word -> PubKey -> HashOid -> HashValue -> SigValue -> Bool
bignVerify'bs l pub oid hash sig
  | l /= 128 && l /= 192 && l /= 256 = error "bignVerify invalid l (must be [128,192,256]"
  | getSize pub /= fromIntegral (2 * l `div` 4) = error "bignVerify invalid pub size (must be [64,92,128])"
  | getSize hash /= fromIntegral (l `div` 4) = error "bignVerify invalid hash size (must be [32,48,64])"
  | getSize sig /= fromIntegral (3 * l `div` 8) = error "bignVerify invalid sig size (must be [48,72,96])"
  | otherwise = unsafePerformIO $ 
      unsafeUseAsCStringLen' (bignStd l) $ \pparams sparams ->
      unsafeUseAsCStringLen' pub $ \ppub spub ->
      unsafeUseAsCStringLen' oid $ \poid soid ->
      unsafeUseAsCStringLen' hash $ \phash shash ->
      unsafeUseAsCStringLen' sig $ \psig ssig -> do
      let e = bignVerify'cptr (castPtr pparams) poid (fromIntegral soid) phash psig ppub
      -- 0 ok, 408 - bad_sig
      case e of
        0 -> return True
        408 -> return False
        _ -> error $ "bignVerify failed: error " ++ show e


{-

data BignWithHash = BignWithHash
  { bignParams :: BignParams
  , hashOid :: BS.ByteString
  }

hbeltOid :: BS.ByteString
bash256Oid :: BS.ByteString
bash392Oid :: BS.ByteString
bash512Oid :: BS.ByteString

sign :: BignWithHash -> PrivKey -> Rng -> HashValue -> Maybe Sig
verify :: BignWithHash -> PubKey -> HashValue -> Sig -> Maybe Bool
-}
