module Bee2.Crypto.Brng
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

foreign import ccall "brngCTR_keep"
  brngCTR_keep'cptr :: SizeT

foreign import ccall "brngCTRStart"
  -- state key[32] iv[32]
  brngCTRStart'cptr :: PVoid -> PCOctet -> PCOctet -> ()

foreign import ccall "brngCTRStepR"
  -- buf count state
  brngCTRStepR'cptr :: PVoid -> SizeT -> PVoid -> IO ()


type RngState = Octets

brngCtrKeep = brngCTR_keep'cptr

brngCtrStart'bs :: Octets -> Octets -> RngState
brngCtrStart'bs key iv
  | getSize key /= 32 = error "brngCtrStart invalid key size (must be 32)"
  | getSize iv /= 32 = error "brngCtrStart invalid iv size (must be 32)"
  | otherwise =
      unsafeCreate' (fromIntegral brngCtrKeep) $ \pstate ->
      unsafeUseAsCStringLen' key $ \pkey skey -> 
      unsafeUseAsCStringLen' iv $ \piv siv -> 
      return $! (brngCTRStart'cptr (castPtr pstate) pkey piv) `seq` 0

brngCtrStep'bs :: RngState -> Octets -> IO Octets
brngCtrStep'bs state buf
  | getSize state /= fromIntegral brngCtrKeep =
      error $ "brngCtrStep invalid state size (must be " ++ show brngCtrKeep ++ ")"
  | getSize buf == 0 = return buf
  | otherwise = 
      unsafeUseAsCStringLen' state $ \pstate sstate -> 
      unsafeUseAsCStringLen' buf $ \pbuf sbuf -> 
      brngCTRStepR'cptr (castPtr pbuf) (fromIntegral (getSize buf)) (castPtr pstate)
      >> return buf

{-


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
