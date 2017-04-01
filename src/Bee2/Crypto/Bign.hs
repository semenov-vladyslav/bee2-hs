module Bee2.Crypto.Bign
  ( 
  ) where

import Bee2.Foreign

{-
-- bign_params is defined as a struct, but we don't need to directly access it's fields
-- so this type stays abstract
-- size: 4+64+64+64+64+64+8
newtype BignParams = BignParams BS.ByteString
type CBignParams = Ptr CUChar

foreign import ccall "bignStdParams"
  bignStdParams'cptr
    :: CBignParams -- bign_params *params
    -> Ptr CChar -- char const *name
    -> ErrT -- err

foreign import ccall "bignGenKeypair"
  bignGenKeypair'cptr
    :: Ptr CUChar -- privkey
    -> Ptr CUChar -- pubkey
    -> CBignParams -- params
    -> RngT -- rng
    -> ErrT -- err

foreign import ccall "bignSign"
  bignSign'cptr
    :: Ptr CUChar -- sig
    -> CBignParams -- params
    -> Ptr CUChar -- oid_der
    -> SizeT -- oid_len
    -> Ptr CUChar -- hash
    -> Ptr CUChar -- privkey
    -> RngT -- rng
    -> Ptr () -- rng_state
    -> ErrT -- err

foreign import ccall "bignSign2"
  bignSign2'cptr
    :: Ptr CUChar -- sig
    -> CBignParams -- params
    -> Ptr CUChar -- oid_der
    -> SizeT -- oid_len
    -> Ptr CUChar -- hash
    -> Ptr CUChar -- privkey
    -> Ptr CUChar -- void const *t
    -> SizeT -- t_len
    -> ErrT -- err

foreign import ccall "bignVerify"
  bignVerify'cptr
    :: CBignParams -- params
    -> Ptr CUChar -- oid_der
    -> SizeT -- oid_len
    -> Ptr CUChar -- hash
    -> Ptr CUChar -- sig
    -> Ptr CUChar -- pubkey
    -> ErrT -- err



bignStdParams :: String -> BignParams
bignStdParams 

bignStd128 :: BignParams
bignStd192 :: BignParams
bignStd256 :: BignParams

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
