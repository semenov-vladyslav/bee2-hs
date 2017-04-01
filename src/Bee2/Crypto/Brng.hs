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

import qualified Data.ByteString as BS
  ( take, drop
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


test'brng = state where
  beltH =
    "B194BAC80A08F53B366D008E584A5DE4" :
    "8504FA9D1BB6C7AC252E72C202FDCE0D" :
    "5BE3D61217B96181FE6786AD716B890B" :
    "5CB0C0FF33C356B835C405AED8E07F99" :
    "E12BDC1AE28257EC703FCCF095EE8DF1" :
    "C1AB76389FE678CAF7C6F860D5BB9C4F" :
    "F33C657B637C306ADD4EA7799EB23D31" :
    "3E98B56E27D3BCCF591E181F4C5AB793" :
    "E9DEE72C8F0C0FA62DDB49F46F739647" :
    "06075316ED247A3739CBA38303A98BF6" :
    "92BD9B1CE5D141015445FBC95E4D0EF2" :
    "682080AA227D642F2687F93490405511" :
    "BE32971343FC9A48A02A885F194B09A1" :
    "7ECDA4D01544AF8CA58450BF66D2E88A" :
    "A2D7465242A8DFB36974C551EB232921" :
    "D4EFD9B43A622875911410EA776CDA1D" :
    []
  beltH'bs = hex2bs $ concat beltH
  key = BS.take 32 . BS.drop 128 $ beltH'bs
  iv = BS.take 32 . BS.drop (128+64) $ beltH'bs
  state = brngCtrStart'bs key iv
  

