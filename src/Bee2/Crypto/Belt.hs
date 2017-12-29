module Bee2.Crypto.Belt
  ( Password, Salt, Key, EKey, Header, Kek
  , beltPBKDF'bs, beltKWPWrap'bs, beltKWPUnwrap'bs, hdr0
  , beltHash'bs, hbelt_oid
  ) where

import Bee2.Defs
import Bee2.Foreign
import Foreign.C.Types
  ( CUInt(..), CSize(..)
  )
import qualified Data.ByteString as BS
  ( pack
  )

foreign import ccall "beltPBKDF"
  beltPBKDF'cptr
    :: POctet -- theta [32]
    -> PCOctet -- pwd
    -> SizeT -- sizeof pwd
    -> SizeT -- iter
    -> PCOctet -- salt
    -> SizeT -- sizeof salt
    -> ErrT -- err

-- bee2/crypto/belt.h 
foreign import ccall "beltKWPWrap"
  beltKWPWrap'cptr 
    :: POctet -- eky [sizeof ky + 16]
    -> PCOctet -- ky
    -> SizeT -- sizeof ky >= 16
    -> PCOctet -- hdr [16]
    -> PCOctet -- kek [16,24,32]
    -> SizeT -- sizeof kek
    -> ErrT -- err
foreign import ccall "beltKWPUnwrap"
  beltKWPUnwrap'cptr 
    :: PCOctet -- ky [sizeof eky - 16]
    -> PCOctet -- eky
    -> SizeT -- sizeof eky >= 32
    -> PCOctet -- hdr [16]
    -> PCOctet -- kek [16,24,32]
    -> SizeT -- sizeof kek
    -> ErrT -- err
foreign import ccall "beltHash"
  beltHash'cptr
    :: POctet -- hash [32]
    -> PCOctet -- const void *src
    -> SizeT -- count
    -> ErrT


type Password = Octets
type Salt = Octets
type Key = Octets -- >= 16
type EKey = Octets -- sizeof key + 16
type Header = Octets -- 16
type Kek = Key -- 32
type Data = Octets -- data to hash, plain text ...
type Hash = Octets -- 32

hbelt_oid = BS.pack $ 6: fromIntegral (length oid) : oid where
  oid = [42,112,0,2,0,34,101,31,81]


beltPBKDF'bs :: Password -> Size -> Salt -> Kek
beltPBKDF'bs pwd iter salt = theta where
  citer = fromIntegral iter
  theta = 
    unsafeCreate' 32 $ \ptheta ->
    unsafeUseAsCStringLen' pwd $ \ppwd spwd -> 
    unsafeUseAsCStringLen' salt $ \psalt ssalt ->
    return $! beltPBKDF'cptr ptheta ppwd spwd citer psalt ssalt

beltKWPWrap'bs :: Header -> Kek -> Key -> EKey
beltKWPWrap'bs hdr kek ky
  | getSize hdr /= 16 = error "beltKWPWrap invalid hdr size (must be 16)"
  | getSize kek /= 32 = error "beltKWPWrap invalid kek size (must be 32)"
  | getSize ky < 16 = error "beltKWPWrap ky size too small (must not be less than 16)"
  | otherwise = 
      unsafeCreate' (getSize ky + 16) $ \peky ->
      unsafeUseAsCStringLen' hdr $ \phdr shdr ->
      unsafeUseAsCStringLen' kek $ \pkek skek ->
      unsafeUseAsCStringLen' ky $ \pky sky ->
      return $! beltKWPWrap'cptr peky pky sky phdr pkek skek

beltKWPUnwrap'bs :: Header -> Kek -> EKey -> Maybe Key
beltKWPUnwrap'bs hdr kek eky
  | getSize hdr /= 16 = error "beltKWPUnwrap invalid hdr size (must be 16)"
  | getSize kek /= 32 = error "beltKWPUnwrap invalid kek size (must be 32)"
  | getSize eky < 32 = error "beltKWPUnwrap eky size too small (must not be less than 32)"
  | otherwise =
      tryUnsafeCreate' eBadToken (getSize eky - 16) $ \pky ->
      unsafeUseAsCStringLen' hdr $ \phdr shdr ->
      unsafeUseAsCStringLen' kek $ \pkek skek ->
      unsafeUseAsCStringLen' eky $ \peky seky ->
      return $! beltKWPUnwrap'cptr pky peky seky phdr pkek skek
      where eBadToken = 410 -- ERR_BAD_KEYTOKEN

beltHash'bs :: Data -> Hash
beltHash'bs d =
  unsafeCreate' 32 $ \phash ->
  unsafeUseAsCStringLen' d $ \pd sd ->
  return $! beltHash'cptr phash pd sd


hdr0 :: Header
hdr0 = repOctet 16 0

test'b
  :: Eq s
  => (s -> String)
  -> (String -> s)
  -> (s -> Size -> s -> s)
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


