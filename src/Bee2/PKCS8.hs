module Bee2.PKCS8
  ( pkcs8'encpri, pkcs8'pri, pkcs8'wrap
  ) where

import Control.Monad
  ( (>=>)
  )
import Bee2.Defs
import Bee2.Crypto.Belt
  ( Password, Salt, Key, EKey, Header, Kek
  , beltPBKDF'bs, beltKWPWrap'bs, beltKWPUnwrap'bs, hdr0
  )
import qualified Data.ASN1.Encoding as ASN1
  ( encodeASN1', decodeASN1'
  )
import qualified Data.ASN1.BinaryEncoding as ASN1
  ( DER(..)
  )
import qualified Data.ASN1.Types as ASN1

import Debug.Trace
  ( trace
  )

liftem :: Either a b -> Maybe b
liftem (Left _) = Nothing
liftem (Right x) = Just x

pkcs8'encpri :: Password -> 
  ( (Size, Salt, Key) -> Octets
  , Octets -> Maybe (Size, Salt, Key)
  )
pkcs8'encpri pwd = (e'bs,d'bs) where
  (e,d) = pkcs8'wrap
  (e',d') = pkcs8'pri
  e'bs (iter, salt, ky) = e (iter, salt, eky) where
    kek = beltPBKDF'bs pwd iter salt
    ky' = e' ky
    eky = beltKWPWrap'bs hdr0 kek ky'
  d'bs = d >=> dd
  dd (iter, salt, eky) = do
    let kek = beltPBKDF'bs pwd iter salt
    ky' <- beltKWPUnwrap'bs hdr0 kek eky
    ky <- d' ky'
    return (iter, salt, ky)

pkcs8'pri ::
  ( Key -> Octets
  , Octets -> Maybe Key
  )
pkcs8'pri = (e'bs,d'bs) where
  (e,d) = pkcs8'asn1
  e'bs = ASN1.encodeASN1' ASN1.DER . e
  d'bs = (liftem . ASN1.decodeASN1' ASN1.DER) >=> d

pkcs8'wrap ::
  ( (Size, Salt, EKey) -> Octets
  , Octets -> Maybe (Size, Salt, EKey)
  )
pkcs8'wrap = (e'bs,d'bs) where
  (e,d) = pkcs8'enc'asn1
  e'bs = ASN1.encodeASN1' ASN1.DER . e
  d'bs = (liftem . ASN1.decodeASN1' ASN1.DER) >=> d

pkcs8'asn1 ::
  ( Key -> [ASN1.ASN1]
  , [ASN1.ASN1] -> Maybe Key
  )
pkcs8'asn1 = (e,d) where
  bign'arc x = 1: 2: 112: 0: 2: 0: 34: 101: 45: x
  bign'pubkey = bign'arc [2,1]
  bign'curve256v1 = bign'arc [3,1]

  e pri =
    [ ASN1.Start ASN1.Sequence -- PrivateKeyInfo
    -- version
    , ASN1.IntVal 0
    -- privateKeyAlgorithm
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID bign'pubkey
    -- parameters
    , ASN1.OID bign'curve256v1 -- DomainParameters.named
    , ASN1.End ASN1.Sequence
    
    -- privateKey
    , ASN1.OctetString pri
    , ASN1.End ASN1.Sequence
    ]
  d
    [ ASN1.Start ASN1.Sequence -- PrivateKeyInfo
    -- version
    , ASN1.IntVal 0
    -- privateKeyAlgorithm
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID v'bign'pubkey
    -- parameters
    , ASN1.OID v'bign'curve256v1 -- DomainParameters.named
    , ASN1.End ASN1.Sequence
    
    -- privateKey
    , ASN1.OctetString pri
    , ASN1.End ASN1.Sequence
    ]
    | bign'pubkey == v'bign'pubkey &&
      bign'curve256v1 == v'bign'curve256v1
      = Just pri
  d _ = Nothing

{-
    , ASN1.Start ASN1.Sequence -- 
    , ASN1.End ASN1.Sequence

    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID oid
    -- parameters
    , ASN1.End ASN1.Sequence
-}

pkcs8'enc'asn1 ::
  ( (Size, Salt, EKey) -> [ASN1.ASN1]
  , [ASN1.ASN1] -> Maybe (Size, Salt, EKey)
  )
pkcs8'enc'asn1 = (e,d) where
  pkcs5'arc x = 1: 2: 840: 113549: 1: 5: x
  belt'arc x = 1: 2: 112: 0: 2: 0: 34: 101: 31: x
  brng'arc x = 1: 2: 112: 0: 2: 0: 34: 101: 47: x

  pbes2'oid = pkcs5'arc [13]
  pbkdf2'oid = pkcs5'arc [12]
  hmac'hbelt'oid = brng'arc [12]
  belt'keywrap256'oid = belt'arc [73]

  e (iter, salt, eky) = 
    [ ASN1.Start ASN1.Sequence -- EncryptedPrivateKeyInfo

    -- privateKeyAlgorithm
    , ASN1.Start ASN1.Sequence -- AlgorithmIdentifier
    -- algorithm
    , ASN1.OID pbes2'oid -- pkcs5-PBES2
    -- parameters
    , ASN1.Start ASN1.Sequence -- PBES2-params

    -- keyDerivationFunc
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID pbkdf2'oid -- pkcs5-PBKDF2
    -- parameters
    , ASN1.Start ASN1.Sequence -- PBKDF2-params
    -- salt
    , ASN1.OctetString salt
    -- iterationCount
    , ASN1.IntVal iiter
    -- keyLength
    -- , ASN1.IntVal 32 -- 32 is the default length of kek
    -- prf
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID hmac'hbelt'oid -- hmac-hbelt
    -- parameters
    , ASN1.Null
    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence

    -- encryptionScheme
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID belt'keywrap256'oid -- belt-keywrap256
    -- parameters
    , ASN1.Null
    , ASN1.End ASN1.Sequence

    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence

    -- privateKey
    , ASN1.OctetString eky

    , ASN1.End ASN1.Sequence
    ]
    where
      iiter = (fromIntegral iter)

  d
    [ ASN1.Start ASN1.Sequence -- EncryptedPrivateKeyInfo

    -- privateKeyAlgorithm
    , ASN1.Start ASN1.Sequence -- AlgorithmIdentifier
    -- algorithm
    , ASN1.OID v'pbes2'oid -- pkcs5-PBES2
    -- parameters
    , ASN1.Start ASN1.Sequence -- PBES2-params

    -- keyDerivationFunc
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID v'pbkdf2'oid -- pkcs5-PBKDF2
    -- parameters
    , ASN1.Start ASN1.Sequence -- PBKDF2-params
    -- salt
    , ASN1.OctetString salt
    -- iterationCount
    , ASN1.IntVal iiter
    -- keyLength
    -- , ASN1.IntVal 32 -- 32 is the default length of kek
    -- prf
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID v'hmac'hbelt'oid -- hmac-hbelt
    -- parameters
    , ASN1.Null
    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence

    -- encryptionScheme
    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID v'belt'keywrap256'oid -- belt-keywrap256
    -- parameters
    , ASN1.Null
    , ASN1.End ASN1.Sequence

    , ASN1.End ASN1.Sequence
    , ASN1.End ASN1.Sequence

    -- privateKey
    , ASN1.OctetString eky

    , ASN1.End ASN1.Sequence
    ]
    | pbes2'oid == v'pbes2'oid &&
      pbkdf2'oid == v'pbkdf2'oid &&
      hmac'hbelt'oid == v'hmac'hbelt'oid &&
      belt'keywrap256'oid == v'belt'keywrap256'oid
      = Just (fromIntegral iiter, salt, eky)
  d _ = Nothing

{-
    , ASN1.Start ASN1.Sequence -- 
    , ASN1.End ASN1.Sequence

    , ASN1.Start ASN1.Sequence --
    -- algorithm
    , ASN1.OID oid
    -- parameters
    , ASN1.End ASN1.Sequence
-}








{-
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
module Lib
    ( someFunc
    ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Internal as BSI
import qualified Data.ASN1.Encoding as ASN1
import qualified Language.C.Inline as C
import           Foreign.C.Types -- CInt, CChar
import           Foreign.Ptr -- Ptr
import           Data.Monoid ((<>))

-- foreign import ccall unsafe "static bee2/crypto/belt.h beltPBKDF"
-- cbeltPBKDF :: CInt -> CInt -> CInt

C.context (C.baseCtx <> C.bsCtx)

C.include "<math.h>"

C.include "<bee2/crypto/belt.h>"
{-
err_t beltPBKDF(
	octet theta[32],		/*!< [out] ключ */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len,			/*!< [in] длина пароля (в октетах) */
	size_t iter,			/*!< [in] число итераций */
	const octet salt[],		/*!< [in] синхропосылка ("соль") */
	size_t salt_len			/*!< [in] длина синхропосылки (в октетах) */
);

err_t beltKWPWrap(
	octet dest[],			/*!< [out] защищенный ключ */
	const octet src[],		/*!< [in] защищаемый ключ */
	size_t count,			/*!< [in] длина src в октетах */
	const octet header[16],	/*!< [in] заголовок ключа */
	const octet theta[],	/*!< [in] ключ защиты */
	size_t len				/*!< [in] длина theta в октетах */
);

err_t beltKWPUnwrap(
	octet dest[],			/*!< [out] ключ */
	const octet src[],		/*!< [in] защищенный ключ */
	size_t count,			/*!< [in] длина src в октетах */
	const octet header[16],	/*!< [in] заголовок ключа */
	const octet theta[],	/*!< [in] ключ защиты */
	size_t len				/*!< [in] длина theta в октетах */
);
-}

type Salt = Octets
type Password = Octets
type Theta = Octets -- 32 byte
type Key = Octets -- 32 .. 64 byte
type Header = Octets -- 16 byte
type EKey = Octets -- sizeof Key + sizeof Header

test :: CInt
test = [C.pure| int{beltECB_keep()} |]

belt'PBKDF :: Int -> Salt -> Password -> Theta
belt'PBKDF iter salt pwd = BSI.unsafeCreate 32 $ \ theta -> do
  let citer :: CInt
      citer = fromIntegral iter
      ptheta :: Ptr CChar
      ptheta = castPtr theta
  return [C.pure| int {beltPBKDF($(char *ptheta), $bs-ptr:pwd, $bs-len:pwd, $(int citer), $bs-ptr:salt, $bs-len:salt)} |]
  return ()
  -- [C.pure| int {beltPBKDF($bs-ptr:theta, $bs-ptr:pwd, $bs-len:pwd, $(int citer), $bs-ptr:salt, $bs-len:salt)} |] where
  -- theta :: Octets
  -- theta = BS.singleton 1
  -- citer :: CInt
  -- citer = fromIntegral iter
{-
-}

beltKWPWrap :: Header -> Theta -> Key -> EKey
beltKWPWrap hdr kek k = undefined

beltKWPUnwrap :: Header -> Theta -> EKey -> Maybe Key
beltKWPUnwrap hdr kek ek = undefined

someFunc :: IO ()
someFunc = do
  x <- [C.exp| double{ cos(1) } |]
  print x

-}
