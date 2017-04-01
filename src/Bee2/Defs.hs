module Bee2.Defs
  ( Octets, Size, getSize, repOctet
  -- , BS.pack, BS.unpack
  -- , BS.decode, BS.encode -- base16
  
  , bs2hex, hex2bs, hexs2lbs
  ) where

import Data.Char
  ( isHexDigit
  )
import Data.Word
  ( Word
  )

import qualified Data.ByteString as BS
  ( ByteString, length, replicate
  )
import qualified Data.ByteString.Char8 as BS
  ( pack, unpack
  )
import qualified Data.ByteString.Base16 as BS
  ( decode, encode
  )
import qualified Data.ByteString.Lazy as LBS
  ( ByteString, fromChunks
  )

type Octets = BS.ByteString
type Size = Word

getSize = BS.length
repOctet = BS.replicate

bs2hex :: BS.ByteString -> String
bs2hex = BS.unpack . BS.encode

hex2bs :: String -> BS.ByteString
hex2bs = fst . BS.decode . BS.pack . filter isHexDigit

hexs2lbs :: [String] -> LBS.ByteString
hexs2lbs = LBS.fromChunks . map hex2bs

