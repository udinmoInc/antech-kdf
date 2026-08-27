-- | Thin Haskell FFI wrapper over libantech_kdf.
{-# LANGUAGE ForeignFunctionInterface #-}
module Antech.Kdf
  ( Config(..)
  , version
  , configDefault
  , hash
  , hashWithConfig
  , verify
  , needsRehash
  ) where

import Control.Exception (Exception, throwIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Word (Word8, Word32)
import Foreign.C.String (CString, peekCString)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable(..), peek, poke, peekByteOff, pokeByteOff)

data AntechError = AntechError String deriving (Show)
instance Exception AntechError

data Config = Config
  { memoryKib :: Word32
  , saltLength :: Word32
  , blockSize :: Word32
  , fanIn :: Word32
  , graph :: Word32
  , outputLength :: Word32
  } deriving (Eq, Show)

data CConfig = CConfig Word32 Word32 Word32 Word32 Word32 Word32

instance Storable CConfig where
  sizeOf _ = 24
  alignment _ = 4
  peek p = CConfig
    <$> peekByteOff p 0
    <*> peekByteOff p 4
    <*> peekByteOff p 8
    <*> peekByteOff p 12
    <*> peekByteOff p 16
    <*> peekByteOff p 20
  poke p (CConfig a b c d e f) = do
    pokeByteOff p 0 a
    pokeByteOff p 4 b
    pokeByteOff p 8 c
    pokeByteOff p 12 d
    pokeByteOff p 16 e
    pokeByteOff p 20 f

foreign import ccall unsafe "antech_version" c_version :: IO CString
foreign import ccall unsafe "antech_free" c_free :: CString -> IO ()
foreign import ccall unsafe "antech_config_default" c_config_default :: Ptr CConfig -> IO CInt
foreign import ccall unsafe "antech_hash_bytes"
  c_hash_bytes :: Ptr Word8 -> CSize -> Ptr CString -> IO CInt
foreign import ccall unsafe "antech_hash_with_config_bytes"
  c_hash_with_config_bytes :: Ptr Word8 -> CSize -> Ptr CConfig -> Ptr CString -> IO CInt
foreign import ccall unsafe "antech_verify_bytes"
  c_verify_bytes :: Ptr Word8 -> CSize -> CString -> IO CInt
foreign import ccall unsafe "antech_needs_rehash"
  c_needs_rehash :: CString -> Ptr CInt -> IO CInt

raiseStatus :: CInt -> IO ()
raiseStatus 0 = pure ()
raiseStatus (-1) = throwIO (AntechError "invalid input")
raiseStatus (-2) = throwIO (AntechError "invalid hash")
raiseStatus (-4) = throwIO (AntechError "invalid config")
raiseStatus st = throwIO (AntechError ("internal error (" ++ show st ++ ")"))

takeString :: CString -> IO String
takeString p
  | p == nullPtr = throwIO (AntechError "null string")
  | otherwise = do
      s <- peekCString p
      c_free p
      pure s

version :: IO String
version = do
  p <- c_version
  if p == nullPtr then pure "0.1.0" else peekCString p

configDefault :: IO Config
configDefault = alloca $ \p -> do
  raiseStatus =<< c_config_default p
  CConfig a b c d e f <- peek p
  pure (Config a b c d e f)

hash :: ByteString -> IO String
hash password = BS.useAsCStringLen password $ \(ptr, len) ->
  alloca $ \out -> do
    raiseStatus =<< c_hash_bytes (castPtr ptr) (fromIntegral len) out
    takeString =<< peek out

hashWithConfig :: ByteString -> Config -> IO String
hashWithConfig password (Config a b c d e f) =
  BS.useAsCStringLen password $ \(ptr, len) ->
    alloca $ \cfg ->
      alloca $ \out -> do
        poke cfg (CConfig a b c d e f)
        raiseStatus =<< c_hash_with_config_bytes (castPtr ptr) (fromIntegral len) cfg out
        takeString =<< peek out

verify :: ByteString -> String -> IO Bool
verify password encoded =
  BS.useAsCStringLen password $ \(ptr, len) ->
    B8.useAsCString (B8.pack encoded) $ \enc -> do
      st <- c_verify_bytes (castPtr ptr) (fromIntegral len) enc
      case st of
        0 -> pure True
        1 -> pure False
        _ -> raiseStatus st >> pure False

needsRehash :: String -> IO Bool
needsRehash encoded =
  B8.useAsCString (B8.pack encoded) $ \enc ->
    alloca $ \out -> do
      raiseStatus =<< c_needs_rehash enc out
      (/= 0) <$> peek out
