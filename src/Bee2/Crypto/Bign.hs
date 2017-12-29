module Bee2.Crypto.Bign
  ( PrivKey, PubKey, HashValue, HashOid, SigValue
  , bignSign2'bs, bignVerify'bs

  , testPri128, testPub128
  , test'bign
  ) where

import Bee2.Defs
import Bee2.Foreign

import Data.Word
  ( Word(..)
  )
import qualified Data.ByteString as BS
  ( replicate, pack
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
type PCBignParams = Ptr () -- void * -> bign_param const *

foreign import ccall "bignStdParams"
  bignStdParams'cptr
    :: PBignParams -- bign_params *params
    -> PCChar -- char const *name
    -> ErrT -- err

foreign import ccall "bignCalcPubkey_deep"
  bignCalcPubkey_deep
    :: SizeT -- n
    -> SizeT -- f_deep
    -> SizeT -- ec_d
    -> SizeT -- ec_deep
    -> SizeT

foreign import ccall "bignCalcPubkey"
  bignCalcPubkey'cptr
    :: POctet -- pubkey
    -> PCBignParams -- params
    -> PCOctet -- privkey
    -> ErrT

foreign import ccall "bignGenKeypair"
  bignGenKeypair'cptr
    :: POctet -- privkey
    -> POctet -- pubkey
    -> PBignParams -- params
    -> FunPtr RngT -- rng
    -> PVoid -- rng_state
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

{-
bignGenKeypair :: Word -> Octets -> Octets -> IO (PrivKey, PubKey)
bignGenKeypair l key iv = 
  | l /= 128 && l /= 192 && l /= 256 = error "bignSign2 invalid l (must be [128,192,256]"
  | otherwise = 
      unsafeCreate' (fromIntegral (l `div` 4)) $ \ppriv ->
      unsafeCreate' (fromIntegral (2 * l `div` 4)) $ \ppub ->
      unsafeUseAsCStringLen' (bignStd l) $ \pparams sparams ->
      return $! bignGenKeypair'cptr ppriv ppub pparams rng rng_state
-}

bignCalcPubkey'bs :: Word -> PrivKey -> PubKey
bignCalcPubkey'bs l priv
  | l /= 128 && l /= 192 && l /= 256 = error "bignCalcPubkey invalid l (must be [128,192,256]"
  | getSize priv /= fromIntegral (l `div` 4) = error "bignCalcPubkey invalid priv size (must be [32,48,64])"
  | otherwise = 
      unsafeCreate' (fromIntegral (l `div` 2)) $ \ppub ->
      unsafeUseAsCStringLen' (bignStd l) $ \pparams sparams ->
      unsafeUseAsCStringLen' priv $ \ppriv spriv ->
      return $! bignCalcPubkey'cptr ppub (castPtr pparams) ppriv

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


testPri128 = hex2bs $ ""
  ++ "1F66B5B84B7339674533F0329C74F218"
  ++"34281FED0732429E0C79235FC273E269"
testPub128 = hex2bs $ ""
  ++ "BD1A5650179D79E03FCEE49D4C2BD5DD"
  ++ "F54CE46D0CF11E4FF87BF7A890857FD0"
  ++ "7AC6A60361E8C8173491686D461B2826"
  ++ "190C2EDA5909054A9AB84D2AB9D99A90"

test'bign = res where
  l = 128
  pri = testPri128
  pub = testPub128
      
  hash_oid = hex2bs $ "0602aabb"
  hash = BS.replicate 32 (fromIntegral 0xaa)
  sig = bignSign2'bs l pri hash_oid hash
  res = bignVerify'bs l pub hash_oid hash sig
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
