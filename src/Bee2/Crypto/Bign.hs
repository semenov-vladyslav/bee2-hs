module Bee2.Crypto.Bign
  ( 
  ) where

import Bee2.Defs
import Bee2.Foreign

import Foreign.C.Types
  ( CUInt(..), CSize(..)
  )
import Foreign.Ptr
  ( FunPtr
  )
import Foreign.C.String
  ( withCString
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
