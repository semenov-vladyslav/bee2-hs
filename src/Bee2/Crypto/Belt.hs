module Bee2.Crypto.Belt
  ( SizeT, Password, Salt, Key, EKey, Header, Kek
  , beltPBKDF'bs, beltKWPWrap'bs, beltKWPUnwrap'bs, hdr0
  , hex2bs, bs2hex
  )where

import Data.Char
  ( isHexDigit
  )

import qualified Data.ByteString as BS
  ( ByteString, length, replicate
  )
import qualified Data.ByteString.Internal as BS
  ( unsafeCreate, unsafeCreateUptoN
  )
import qualified Data.ByteString.Unsafe as BS
  ( unsafeUseAsCStringLen
  )
import qualified Data.ByteString.Char8 as BS
  ( pack, unpack
  )
import qualified Data.ByteString.Base16 as BS
  ( decode, encode
  )

import Foreign.C.Types
  ( CUInt(..), CUChar, CSize(..)
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


type ErrT = CUInt
foreign import ccall "beltPBKDF"
  beltPBKDF'cptr
    :: Ptr CUChar -- theta [32]
    -> Ptr CUChar -- pwd
    -> CSize -- sizeof pwd
    -> CSize -- iter
    -> Ptr CUChar -- salt
    -> CSize -- sizeof salt
    -> CUInt -- err
-- beltPBKDF'cptr = undefined

-- bee2/crypto/belt.h 
foreign import ccall "beltKWPWrap"
  beltKWPWrap'cptr 
    :: Ptr CUChar -- eky [sizeof ky + 16]
    -> Ptr CUChar -- ky
    -> CSize -- sizeof ky >= 16
    -> Ptr CUChar -- hdr [16]
    -> Ptr CUChar -- kek [16,24,32]
    -> CSize -- sizeof kek
    -> CUInt -- err
-- beltKWPWrap'cptr = undefined
foreign import ccall "beltKWPUnwrap"
  beltKWPUnwrap'cptr 
    :: Ptr CUChar -- ky [sizeof eky - 16]
    -> Ptr CUChar -- eky
    -> CSize -- sizeof eky >= 32
    -> Ptr CUChar -- hdr [16]
    -> Ptr CUChar -- kek [16,24,32]
    -> CSize -- sizeof kek
    -> CUInt -- err


type SizeT = Int
type Password = BS.ByteString
type Salt = BS.ByteString
type Key = BS.ByteString -- >= 16
type EKey = BS.ByteString -- sizeof key + 16
type Header = BS.ByteString -- 16
type Kek = Key -- 32

unsafeUseAsCStringLen'
  :: BS.ByteString
  -> (Ptr CUChar -> CSize -> IO a)
  -> IO a
unsafeUseAsCStringLen' bs f =
  BS.unsafeUseAsCStringLen bs $ \(p,s) -> f (castPtr p) (fromIntegral s)

unsafeCreate'
  :: Int
  -> (Ptr CUChar -> IO ErrT)
  -> BS.ByteString
unsafeCreate' n f = bs where
  bs = BS.unsafeCreateUptoN n $ \p -> do
    err <- f (castPtr p)
    case err of
      0 -> return n
      _ -> error $ "unsafeCreate' error: " ++ show err

tryUnsafeCreate'
  :: ErrT
  -> Int
  -> (Ptr CUChar -> IO ErrT)
  -> Maybe BS.ByteString
tryUnsafeCreate' e'nothing n f = if n == BS.length bs then Just bs else Nothing where
  bs = BS.unsafeCreateUptoN n $ \p -> do
    err <- f (castPtr p)
    case err of
      0 -> return n
      _ | err == e'nothing -> return 0
        | otherwise -> error $ "tryUnsafeCreate' error: " ++ show err


beltPBKDF'bs :: Password -> SizeT -> Salt -> Kek
beltPBKDF'bs pwd iter salt = theta where
  citer = fromIntegral iter
  theta = 
    unsafeCreate' 32 $ \ptheta ->
    unsafeUseAsCStringLen' pwd $ \ppwd spwd -> 
    unsafeUseAsCStringLen' salt $ \psalt ssalt ->
    return $! beltPBKDF'cptr ptheta ppwd spwd citer psalt ssalt

beltKWPWrap'bs :: Header -> Kek -> Key -> EKey
beltKWPWrap'bs hdr kek ky
  | BS.length hdr /= 16 = error "beltKWPWrap invalid hdr size (must be 16)"
  | BS.length kek /= 32 = error "beltKWPWrap invalid kek size (must be 32)"
  | BS.length ky < 16 = error "beltKWPWrap ky size too small (must not be less than 16)"
  | otherwise = 
      unsafeCreate' (BS.length ky + 16) $ \peky ->
      unsafeUseAsCStringLen' hdr $ \phdr shdr ->
      unsafeUseAsCStringLen' kek $ \pkek skek ->
      unsafeUseAsCStringLen' ky $ \pky sky ->
      return $! beltKWPWrap'cptr peky pky sky phdr pkek skek

beltKWPUnwrap'bs :: Header -> Kek -> EKey -> Maybe Key
beltKWPUnwrap'bs hdr kek eky
  | BS.length hdr /= 16 = error "beltKWPUnwrap invalid hdr size (must be 16)"
  | BS.length kek /= 32 = error "beltKWPUnwrap invalid kek size (must be 32)"
  | BS.length eky < 32 = error "beltKWPUnwrap eky size too small (must not be less than 32)"
  | otherwise =
      tryUnsafeCreate' eBadToken (BS.length eky - 16) $ \pky ->
      unsafeUseAsCStringLen' hdr $ \phdr shdr ->
      unsafeUseAsCStringLen' kek $ \pkek skek ->
      unsafeUseAsCStringLen' eky $ \peky seky ->
      return $! beltKWPUnwrap'cptr pky peky seky phdr pkek skek
      where eBadToken = 410 -- ERR_BAD_KEYTOKEN

hdr0 :: Header
hdr0 = BS.replicate 16 0


bs2hex :: BS.ByteString -> String
bs2hex = BS.unpack . BS.encode

hex2bs :: String -> BS.ByteString
hex2bs = fst . BS.decode . BS.pack . filter isHexDigit

test'b
  :: Eq s
  => (s -> String)
  -> (String -> s)
  -> (s -> SizeT -> s -> s)
  -> (s -> s -> s -> s)
  -> Bool
test'b s2hex hex2s pbkdf wrap =
  trace ("p = " ++ s2hex p) $ 
  trace ("s = " ++ s2hex s) $ 
  trace ("t = " ++ s2hex t) $ 
  trace ("t' = " ++ s2hex t') $ 
  trace ("h = " ++ s2hex h) $ 
  trace ("d = " ++ s2hex d) $ 
  trace ("y = " ++ s2hex y) $ 
  trace ("y' = " ++ s2hex y') $ 
  t == t' && y == y' where
  ([p,s,t,h,d,y], c) = (map hex2s $ fst test'data, snd test'data)
  t' = pbkdf p c s
  y' = wrap h d t'


test'bs = test'b bs2hex hex2bs beltPBKDF'bs beltKWPWrap'bs

test'data = ([p,s,t,h,d,y], c) where
  p = "42313934 42414338 30413038 46353342"
  c = 10000
  s = "BE329713 43FC9A48 A02A885F 194B09A1"
  t = "D9024724 82130F3B 77D09303 03DD7E4E 68630CC0 2B56A8B2 AFA74F09 6BCAC971"
  h = "00000000 00000000 00000000 00000000"
  d = "1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269"
  y = "248E0CD7 639B1237 76F1CEC1 FCECE708 C2DFC53F 78ECEA6C 33B4C3C1 E6183AD6 D8A18CFA F540976E 1022B89D BA32DA18"
  
-- foreign import ccall unsafe "static bee2/crypto/belt.h beltPBKDF"
-- cbeltPBKDF :: CInt -> CInt -> CInt


