module Bee2.Crypto.Bash
  ( HashValue, bashHash'bs, test'bash
  ) where

import Bee2.Defs
import Bee2.Foreign
import Foreign.C.Types
  ( CInt(..), CUInt(..), CSize(..)
  )

import qualified Data.ByteString as BS
  ( ByteString, length, take
  )
import qualified Data.ByteString.Lazy as LBS
  ( ByteString, length, foldlChunks, take
  )

foreign import ccall "bash_keep"
  bashKeep'cptr :: SizeT

foreign import ccall "bashStart"
  bashStart'cptr
    :: PVoid -- state
    -> SizeT -- l
    -> ()

foreign import ccall "bashStepH"
  bashStepH'cptr
    :: PCVoid -- buf
    -> SizeT -- count
    -> PVoid -- state
    -> ()

foreign import ccall "bashStepG"
  bashStepG'cptr
    :: POctet -- hash
    -> SizeT -- hash_len
    -> PVoid -- state
    -> ()

foreign import ccall "bashStepV"
  bashStepV'cptr
    :: PCOctet -- hash
    -> SizeT -- hash_len
    -> PVoid -- state
    -> CInt

foreign import ccall "bashHash"
  bashHash'cptr
    :: POctet -- hash
    -> SizeT -- l
    -> PCVoid -- src
    -> SizeT -- count
    -> ErrT

type BashState = Octets
type HashValue = Octets

bashKeep :: Int
bashKeep = fromIntegral bashKeep'cptr

bashStepH'bs' :: POctet -> BS.ByteString -> POctet
bashStepH'bs' pstate dat =
  unsafePerformIO $ 
  unsafeUseAsCStringLen' dat $ \pdat sdat -> 
  return $! (bashStepH'cptr (castPtr pdat) sdat (castPtr pstate)) `seq` pstate

bashStepH'bs :: BashState -> BS.ByteString -> BashState
bashStepH'bs state dat = 
  unsafePerformIO $ 
  unsafeUseAsCStringLen' state $ \pstate sstate -> 
  unsafeUseAsCStringLen' dat $ \pdat sdat -> 
  return $! (bashStepH'cptr (castPtr pdat) sdat (castPtr pstate)) `seq` state

bashHash'bs :: Word -> BS.ByteString -> HashValue
bashHash'bs l dat
  | not (0 < l && (l `mod` 16 == 0) && l <= 256) =
    error $ "bashHash invalid level (must be 16*k, k<-[1..16])"
  | otherwise =
      unsafeCreate' (fromIntegral (l `div` 4)) $ \phash ->
      unsafeUseAsCStringLen' dat $ \pdat sdat -> 
      return $! bashHash'cptr phash (fromIntegral l) (castPtr pdat) sdat

bashHash'lbs :: Word -> LBS.ByteString -> HashValue
bashHash'lbs l dat
  | not (0 < l && (l `mod` 16 == 0) && l <= 256) =
    error $ "bashHash invalid level (must be 16*k, k<-[1..16])"
  | otherwise =
      unsafeCreate' (fromIntegral (l `div` 4)) $ \phash -> 
      return $! (unsafeCreate' bashKeep $ \pstate -> do
      let pstate' = (bashStart'cptr (castPtr pstate) (fromIntegral l)) `seq` pstate
      let pstate'' = LBS.foldlChunks bashStepH'bs' pstate' dat
      return $! bashStepG'cptr phash (fromIntegral (l `div` 4)) (castPtr pstate'') `seq` 0) `seq` 0

test'bash = [a21,a22,a23,a24,a25,a26,a27,a28,a29,a210,a212] where
  bashTest :: Word -> BS.ByteString -> LBS.ByteString -> BS.ByteString -> Bool
  bashTest l dat dat' hv0 =
    -- trace ("dat = " ++ bs2hex dat) $
    -- trace ("hv = " ++ bs2hex hv) $
    -- trace ("hv' = " ++ bs2hex hv') $
      hv == hv0 && hv' == hv0
    where
      hv = bashHash'bs l dat
      hv' = bashHash'lbs l dat'

  datChunks = -- 192 bytes
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
    []
  dat = hex2bs $ concat datChunks
  dat' = hexs2lbs $ datChunks
  bashTest' :: Word -> Int -> String -> Bool
  bashTest' l n hv = bashTest l (BS.take n dat) (LBS.take n' dat') (hex2bs hv) where
    n' = fromIntegral n

  -- A.2.1
  a21 = bashTest' 128 0 $ ""
    ++ "114C3DFAE373D9BCBC3602D6386F2D6A"
    ++ "2059BA1BF9048DBAA5146A6CB775709D"
  -- A.2.2
  a22 = bashTest' 128 127 $ ""
    ++ "3D7F4EFA00E9BA33FEED259986567DCF"
    ++ "5C6D12D51057A968F14F06CC0F905961"
  -- A.2.3
  a23 = bashTest' 128 128 $ ""
    ++ "D7F428311254B8B2D00F7F9EEFBD8F30"
    ++ "25FA87C4BABD1BDDBE87E35B7AC80DD6"
  -- A.2.4
  a24 = bashTest' 128 135 $ ""
    ++ "1393FA1B65172F2D18946AEAE576FA1C"
    ++ "F54FDD354A0CB2974A997DC4865D3100"
  -- A.2.5
  a25 = bashTest' 192 95 $ ""
    ++ "64334AF830D33F63E9ACDFA184E32522"
    ++ "103FFF5C6860110A2CD369EDBC04387C"
    ++ "501D8F92F749AE4DE15A8305C353D64D"
  -- A.2.6
  a26 = bashTest' 192 96 $ ""
    ++ "D06EFBC16FD6C0880CBFC6A4E3D65AB1"
    ++ "01FA82826934190FAABEBFBFFEDE93B2"
    ++ "2B85EA72A7FB3147A133A5A8FEBD8320"
  -- A.2.7
  a27 = bashTest' 192 108 $ ""
    ++ "FF763296571E2377E71A1538070CC0DE"
    ++ "88888606F32EEE6B082788D246686B00"
    ++ "FC05A17405C5517699DA44B7EF5F55AB"
  -- A.2.8
  a28 = bashTest' 256 63 $ ""
    ++ "2A66C87C189C12E255239406123BDEDB"
    ++ "F19955EAF0808B2AD705E249220845E2"
    ++ "0F4786FB6765D0B5C48984B1B16556EF"
    ++ "19EA8192B985E4233D9C09508D6339E7"
  -- A.2.9
  a29 = bashTest' 256 64 $ ""
    ++ "07ABBF8580E7E5A321E9B940F667AE20"
    ++ "9E2952CEF557978AE743DB086BAB4885"
    ++ "B708233C3F5541DF8AAFC3611482FDE4"
    ++ "98E58B3379A6622DAC2664C9C118A162"
  -- A.2.10
  a210 = bashTest' 256 127 $ ""
    ++ "526073918F97928E9D15508385F42F03"
    ++ "ADE3211A23900A30131F8A1E3E1EE21C"
    ++ "C09D13CFF6981101235D895746A4643F"
    ++ "0AA62B0A7BC98A269E4507A257F0D4EE"
  -- no A.2.11 test
  -- A.2.12
  a212 = bashTest' 256 192 $ ""
    ++ "8724C7FF8A2A83F22E38CB9763777B96"
    ++ "A70ABA3444F214C763D93CD6D19FCFDE"
    ++ "6C3D3931857C4FF6CCCD49BD99852FE9"
    ++ "EAA7495ECCDD96B571E0EDCF47F89768"



