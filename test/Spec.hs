{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

import Prelude hiding (sequence)
import Recode
import Internal (myOptions)
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)
import Data.Text (Text)
import Data.Aeson.TH (deriveJSON)
import System.Directory (getDirectoryContents)
import Text.Printf (printf)
import Data.Char (isSpace)
import qualified Data.List as List
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LBC8
import qualified Data.ByteString as BS

main :: IO ()
main = do
  humanFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/human"
  fooFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/foo"
  defaultMain
    [ testGroup "Human" (map (testEncoding "human" encHuman) humanFiles)
    , testGroup "Foo" (map (testEncoding "foo" encFoo) fooFiles)
    ]

isChildTestDir :: String -> Bool
isChildTestDir s = s /= "." && s /= ".." && s /= "definition.asn1"

data Human = Human
  { humanName :: Text
  , humanFirstWords :: Text
  , humanAge :: Maybe Age
  }

data Age = AgeBiblical Integer | AgeModern Integer

data Foo = Foo
  { fooSize :: Integer
  , fooIdentifier :: ObjectIdentifier
  }

testEncoding :: Aeson.FromJSON a => String -> Enc a -> String -> Test
testEncoding name enc dirNum = testCase dirNum $ do
  let path = "sample/" ++ name ++ "/" ++ dirNum ++ "/"
  valueLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.json")
  resultLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.der.base64")
  a <- case Aeson.eitherDecode valueLbs of
    Left err -> fail ("bad json file for model [" ++ name ++ "] test [" ++ dirNum ++ "], error was: " ++ err)
    Right a -> return a
  let encodedLbs = encodeBer enc a
  hexByteString encodedLbs @?= LBC8.unpack (LBC8.filter (not . isSpace) resultLbs)

encHuman :: Enc Human
encHuman = sequence
  [ required "name" humanName utf8String
  , defaulted "first-words" humanFirstWords utf8String "Hello World"
  , optional "age" humanAge encAge
  ]

encFoo :: Enc Foo
encFoo = sequence
  [ required "size" fooSize integer
  , required "identifier" fooIdentifier objectIdentifier
  ]

encAge :: Enc Age
encAge = choice [AgeBiblical 0, AgeModern 0] $ \x -> case x of
  AgeBiblical n -> option 0 "biblical" n $ tag 0 $ integerRanged 0 1000
  AgeModern n -> option 1 "modern" n $ tag 1 $ integerRanged 0 100

hexByteString :: LB.ByteString -> String
hexByteString = LB.foldr (\w xs -> printf "%02X" w ++ xs) []

deriving instance Aeson.ToJSON ObjectIdentifier
deriving instance Aeson.FromJSON ObjectIdentifier

$(deriveJSON (myOptions "Age") ''Age)
$(deriveJSON (myOptions "Human") ''Human)
$(deriveJSON (myOptions "Foo") ''Foo)

