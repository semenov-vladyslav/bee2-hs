module Bee2.Crypto.Brng
  (
  ) where

import Bee2.Foreign

{-
foreign import ccall "brngCTR_keep"
  brngCTR_keep'c :: () -> CSize

foreign import ccall "brngCTRStart"
  brngCTRStart'c :: Ptr () -> Ptr CUChar -> Ptr CUChar -> IO ()

foreign import ccall "brngCTRStepR"
  brngCTRStepR'c :: Ptr () -> CSize -> Ptr () -> IO ()



type Key = BS.ByteString
type IV = BS.ByteString
type RngState = BS.ByteString

mk'brngCTR :: Key -> IV -> RngState
mk'brngCTR key iv = state where
  keep = brngCTR_keep'c ()
  state = 
    unsafeCreate' (fromIntegral keep) $ \pstate ->
    unsafeUseAsCStringLen' key $ \pkey skey -> 
    unsafeUseAsCStringLen' iv $ \piv siv -> do
    err <- return $! brngCTRStart'c pstate pkey piv
    return ()
-}
