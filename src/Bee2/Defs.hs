module Bee2.Defs
  ( Octets, Size, getSize, repOctet
  -- , BS.pack, BS.unpack
  -- , BS.decode, BS.encode -- base16
  
  , bs2hex, hex2bs
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

type Octets = BS.ByteString
type Size = Word

getSize = BS.length
repOctet = BS.replicate

bs2hex :: Octets -> String
bs2hex = BS.unpack . BS.encode

hex2bs :: String -> Octets
hex2bs = fst . BS.decode . BS.pack . filter isHexDigit

