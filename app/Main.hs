module Main where

import Bee2.Defs
import Bee2.Crypto.Belt
import Bee2.PKCS8

import Data.Functor.Identity
import Control.Monad.IO.Class
import Control.Monad.Trans.State
import Control.Monad.Trans.Cont
import Control.Monad.Trans.Except

import qualified Data.ByteString as BS
  ( ByteString, getContents, putStr, readFile, writeFile
  )
import qualified Data.ByteString.Char8 as BS
  ( pack
  )
import qualified Data.ByteString.Base16 as BS
  ( decode, encode
  )

import qualified Data.ByteString.Lazy as LBS
  ( ByteString, getContents, putStr, readFile, writeFile
  )
import qualified Data.ByteString.Lazy.Char8 as LBS
  ( pack
  )
import qualified Data.ByteString.Base16.Lazy as LBS
  ( decode, encode
  )

import System.Environment
  ( getArgs
  )
import System.Exit
  ( die
  )

type CanUseStd = (Bool,Bool) -- (Stdin, Stdout)
type Args = (CanUseStd,[String])

data ArgDir = In | Out
type ArgName = String
type ArgDefault = Bool
type ArgDesc = (ArgName,ArgDefault)

-- StateT Args (ExceptT String Identity) (IO BS.ByteString)
-- in'bs' :: ArgDesc -> StateT Args (Either String) (IO BS.ByteString)
-- in'bs' ad = StateT $ in'bs ad

st :: (Args -> Either String (a, Args)) -> StateT Args (Either String) a
st = StateT

in'n :: ArgDesc -> Args -> Either String (Size, Args)
in'n (an,_) (std,arg:args) =
  case readsPrec 0 arg of
    [(n,"")] -> return (n, (std,args))
    _ -> Left ("cannot parse int arg " ++ an)
in'n (an,_) (std,[]) = Left ("no argument for " ++ an)

in'str :: ArgDesc -> Args -> Either String (BS.ByteString, Args)
in'str (an,_) (std,arg:args) = return (BS.pack arg, (std,args))


-- strict ByteString

in'bs :: ArgDesc -> Args -> Either String (IO BS.ByteString, Args)
in'bs (an,_) ((stdin,stdout),(('-':'-':'i':'n':'-':fmt):args))
  | stdin = do
      cvt <- fmt'bs fmt
      return (fmap cvt $ BS.getContents, ((False,stdout),args))
  | otherwise = Left ("cannot use stdin to get arg " ++ an)
in'bs _ (std,(('-':'-':'i':'f':'-':fmt):fn:args)) = do
  cvt <- fmt'bs fmt
  return (fmap cvt $ BS.readFile fn, (std,args))
in'bs _ (std,(hex:args)) = Right (return $ hex'bs $ hex, (std,args)) where
  hex'bs = fst . BS.decode . BS.pack . filter (/=' ')
in'bs (_,True) ((True,stdout),[]) = return (BS.getContents, ((False,stdout),[]))
in'bs (an,_) (_,[]) = Left ("no argument for " ++ an)

out'bs :: ArgDesc -> Args -> Either String (BS.ByteString -> IO (), Args)
out'bs (an,_) ((stdin,stdout),(('-':'-':'o':'u':'t':'-':fmt):args))
  | stdout = do
      cvt <- bs'fmt fmt
      return (BS.putStr . cvt, ((stdin,False),args))
  | otherwise = Left ("cannot use stdout to put arg " ++ an)
out'bs _ (std,(('-':'-':'o':'f':'-':fmt):fn:args)) = do
  cvt <- bs'fmt fmt
  return (BS.writeFile fn . cvt, (std,args))
out'bs (_,True) ((stdin,True),[]) = return (BS.putStr, ((stdin,False),[]))
out'bs (an,_) (_,[]) = Left ("no argument for " ++ an)
out'bs (an,_) args = Left ("cannot parse " ++ an ++ ": " ++ show args)

fmt'bs :: String -> Either String (BS.ByteString -> BS.ByteString)
fmt'bs "bin" = Right id
fmt'bs "hex" = Right (fst . BS.decode)
fmt'bs fmt = Left ("unknown format: " ++ fmt)

bs'fmt :: String -> Either String (BS.ByteString -> BS.ByteString)
bs'fmt "bin" = Right id
bs'fmt "hex" = Right BS.encode
bs'fmt fmt = Left ("unknown format: " ++ fmt)



-- lazy ByteString

in'lbs :: ArgDesc -> Args -> Either String (IO LBS.ByteString, Args)
in'lbs (an,_) ((stdin,stdout),(('-':'-':'i':'n':'-':fmt):args))
  | stdin = do
      cvt <- fmt'lbs fmt
      return (fmap cvt $ LBS.getContents, ((False,stdout),args))
  | otherwise = Left ("cannot use stdin to get arg " ++ an)
in'lbs _ (std,(('-':'-':'i':'f':'-':fmt):fn:args)) = do
  cvt <- fmt'lbs fmt
  return (fmap cvt $ LBS.readFile fn, (std,args))
in'lbs _ (std,(hex:args)) = Right (return $ hex'lbs $ hex, (std,args)) where
  hex'lbs = fst . LBS.decode . LBS.pack . filter (/=' ')
in'lbs (_,True) ((True,stdout),[]) = return (LBS.getContents, ((False,stdout),[]))
in'lbs (an,_) (_,[]) = Left ("no argument for " ++ an)

out'lbs :: ArgDesc -> Args -> Either String (LBS.ByteString -> IO (), Args)
out'lbs (an,_) ((stdin,stdout),(('-':'-':'o':'u':'t':'-':fmt):args))
  | stdout = do
      cvt <- lbs'fmt fmt
      return (LBS.putStr . cvt, ((stdin,False),args))
  | otherwise = Left ("cannot use stdout to put arg " ++ an)
out'lbs _ (std,(('-':'-':'o':'f':'-':fmt):fn:args)) = do
  cvt <- lbs'fmt fmt
  return (LBS.writeFile fn . cvt, (std,args))
out'lbs (_,True) ((stdin,True),[]) = return (LBS.putStr, ((stdin,False),[]))
out'lbs (an,_) (_,[]) = Left ("no argument for " ++ an)

fmt'lbs :: String -> Either String (LBS.ByteString -> LBS.ByteString)
fmt'lbs "bin" = Right id
fmt'lbs "hex" = Right (fst . LBS.decode)
fmt'lbs fmt = Left ("unknown format: " ++ fmt)

lbs'fmt :: String -> Either String (LBS.ByteString -> LBS.ByteString)
lbs'fmt "bin" = Right id
lbs'fmt "hex" = Right LBS.encode
lbs'fmt fmt = Left ("unknown format: " ++ fmt)




run :: String -> Args -> Either String (IO ())

run "kwp" args = do
  ((get'kek, get'key, put'ekey), args') <- flip runStateT args $ do
    get'kek <- st $ in'bs ("kek",True)
    get'key <- st $ in'bs ("key",False)
    put'ekey <- st $ out'bs ("ekey",True)
    return $ (get'kek, get'key, put'ekey)

  case args' of
    (_,[]) -> return $ do
      key <- get'key
      kek <- get'kek
      let ekey = kwp kek key
      put'ekey ekey
    _ -> Left "extra args provided"
    where
      kwp = beltKWPWrap'bs hdr0

run "uwp" args = do
  ((get'kek, get'ekey, put'key), args') <- flip runStateT args $ do
    get'kek <- st $ in'bs ("kek",False)
    get'ekey <- st $ in'bs ("ekey",True)
    put'key <- st $ out'bs ("key",True)
    return $ (get'kek, get'ekey, put'key)

  case args' of
    (_,[]) -> return $ do
      kek <- get'kek
      ekey <- get'ekey
      let mkey = uwp kek ekey
      case mkey of
        Just key -> put'key key
        _ -> die "Failed to unwrap key: bad token."
    _ -> Left "extra args provided"
    where
      uwp = beltKWPUnwrap'bs hdr0

run "pbkdf2" args = do
  ((n, get'salt, pwd, put'kek), args') <- flip runStateT args $ do
    n <- st $ in'n ("iter",False)
    get'salt <- st $ in'bs ("salt",False)
    pwd <- st $ in'str ("pwd",False)
    put'kek <- st $ out'bs ("kek",True)
    return $ (n, get'salt, pwd, put'kek)

  case args' of
    (_,[]) -> return $ do
      salt <- get'salt
      let kek = pbkdf2 n salt pwd
      put'kek kek
    _ -> Left "extra args provided"
    where
      pbkdf2 n salt pwd = beltPBKDF'bs pwd n salt

run "pkcs8-encpri" args = do
  ((n, get'salt, pwd, get'key, put'pkcs), args') <- flip runStateT args $ do
    n <- st $ in'n ("iter",False)
    get'salt <- st $ in'bs ("salt",False)
    pwd <- st $ in'str ("pwd",False)
    get'key <- st $ in'bs ("key",True)
    put'pkcs <- st $ out'bs ("pkcs8",True)
    return $ (n, get'salt, pwd, get'key, put'pkcs)

  case args' of
    (_,[]) -> return $ do
      salt <- get'salt
      key <- get'key
      let pkcs = fst (pkcs8'encpri pwd) (n, salt, key)
      put'pkcs pkcs
    _ -> Left "extra args provided"

run "d-pkcs8-encpri" args = do
  ((pwd, get'pkcs, put'key), args') <- flip runStateT args $ do
    pwd <- st $ in'str ("pwd",False)
    get'pkcs <- st $ in'bs ("pkcs8",True)
    put'key <- st $ out'bs ("key",True)
    return $ (pwd, get'pkcs, put'key)

  case args' of
    (_,[]) -> return $ do
      pkcs <- get'pkcs
      case snd (pkcs8'encpri pwd) pkcs of
        Just (n, salt, key) -> put'key key
        Nothing -> die "Failed to parse and unwrap pkcs8."
    _ -> Left "extra args provided"

run "pkcs8-pri" args = do
  ((get'key, put'pkcs), args') <- flip runStateT args $ do
    get'key <- st $ in'bs ("key",True)
    put'pkcs <- st $ out'bs ("pkcs8",True)
    return $ (get'key, put'pkcs)

  case args' of
    (_,[]) -> return $ do
      key <- get'key
      let pkcs = fst pkcs8'pri key
      put'pkcs pkcs
    _ -> Left "extra args provided"

run "d-pkcs8-pri" args = do
  ((get'pkcs, put'key), args') <- flip runStateT args $ do
    get'pkcs <- st $ in'bs ("pkcs8",True)
    put'key <- st $ out'bs ("key",True)
    return $ (get'pkcs, put'key)

  case args' of
    (_,[]) -> return $ do
      pkcs <- get'pkcs
      case snd pkcs8'pri pkcs of
        Just key -> put'key key
        Nothing -> die "Failed to parse pkcs8."
    _ -> Left "extra args provided"

run "pkcs8-encwrap" args = do
  ((n, get'salt, get'ekey, put'pkcs), args') <- flip runStateT args $ do
    n <- st $ in'n ("iter",False)
    get'salt <- st $ in'bs ("salt",False)
    get'ekey <- st $ in'bs ("ekey",True)
    put'pkcs <- st $ out'bs ("pkcs8",True)
    return $ (n, get'salt, get'ekey, put'pkcs)

  case args' of
    (_,[]) -> return $ do
      salt <- get'salt
      ekey <- get'ekey
      let pkcs = fst pkcs8'wrap (n, salt, ekey)
      put'pkcs pkcs
    _ -> Left "extra args provided"

run "d-pkcs8-encwrap" args = do
  ((get'pkcs, put'salt, put'ekey), args') <- flip runStateT args $ do
    get'pkcs <- st $ in'bs ("pkcs8",False)
    -- n <- st $ out'n ("iter",False)
    put'salt <- st $ out'bs ("salt",False)
    put'ekey <- st $ out'bs ("ekey",True)
    return $ (get'pkcs, put'salt, put'ekey)

  case args' of
    (_,[]) -> return $ do
      pkcs <- get'pkcs
      case snd pkcs8'wrap pkcs of
        Just (n, salt, ekey) -> do
          putStr (show n)
          put'salt salt
          put'ekey ekey
        Nothing ->
          die "Failed to parse pkcs8"
    _ -> Left "extra args provided"

run "io" args = do
  ((i, o), args') <- flip runStateT args $ do
    get <- st $ in'bs ("i",True)
    put <- st $ out'bs ("o",True)
    return $ (get, put)

  case args' of
    (_,[]) -> return $ i >>= o
    _ -> Left "extra args provided"

run "lio" args = do
  ((i, o), args') <- flip runStateT args $ do
    get <- st $ in'lbs ("i",True)
    put <- st $ out'lbs ("o",True)
    return $ (get, put)

  case args' of
    (_,[]) -> return $ i >>= o
    _ -> Left "extra args provided"

run cmd _ =
  Left ("unknown cmd: " ++ cmd)

usage = "Usage:\n"
      -- ++ "gen size:[32]|n key:[out-bin]|out-hex|<of-bin>\n"
      ++ "io i o\n"
      ++ "kwp kek key ekey\n"
      ++ "uwp kek ekey key\n"
      ++ "pbkdf2 iter salt pwd kek\n"
      ++ "pkcs8-encpri iter salt pwd key pkcs8\n"
      ++ "d-pkcs8-encpri pwd pkcs8 key\n"
      ++ "pkcs8-pri key pkcs8\n"
      ++ "d-pkcs8-pri pkcs8 key\n"
      ++ "pkcs8-encwrap iter salt ekey pkcs8\n"
      ++ "d-pkcs8-encwrap pkcs8 salt ekey\n"
      ++ "\n"
      ++ "Examples:\n"
      ++ "io 42313934424143383041303846353342 --of-bin stdpwd\n"
      ++ "io BE32971343FC9A48A02A885F194B09A1 --of-bin stdsalt\n"
      ++ "pbkdf2 10000 --if-bin stdsalt B194BAC80A08F53B --of-bin stdkek\n"
      ++ "io 1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269 --of-bin stdpri\n"
      ++ "kwp --if-bin stdkek --if-bin stdpri --of-bin stdepri\n"
      ++ "uwp --if-bin stdkek --if-bin stdepri --of-bin stddepri\n"
      ++ "pkcs8-encpri 10000 --if-bin stdsalt B194BAC80A08F53B --if-bin stdpri --of-bin pkcs8epri\n"
      ++ "d-pkcs8-encpri B194BAC80A08F53B --if-bin pkcs8epri --of-bin pkcs8depri\n"

main :: IO ()
main = do
  args <- getArgs
  case args of
    cmd:args ->
      case run cmd ((True,True),args) of
        Right f -> f
        Left e -> die e -- putStrLn e >> usage
    _ -> putStrLn usage
