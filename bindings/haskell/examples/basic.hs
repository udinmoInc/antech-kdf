module Main where

import Antech.Kdf
import qualified Data.ByteString.Char8 as B8

main :: IO ()
main = do
  stored <- hash (B8.pack "correct_horse_battery_staple")
  ok <- verify (B8.pack "correct_horse_battery_staple") stored
  if not ok then error "verify failed" else pure ()
  cfg0 <- configDefault
  let cfg = cfg0 { memoryKib = 1024 }
  custom <- hashWithConfig (B8.pack "pw") cfg
  needs <- needsRehash custom
  putStrLn ("needs_rehash " ++ show needs)
  putStrLn stored
