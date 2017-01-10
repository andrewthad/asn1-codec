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
import Net.Snmp.Types
import Data.ByteString (ByteString)
import Numeric (readHex)
import qualified Data.Text as Text
import qualified Data.List as List
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LBC8
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString as BS
import qualified Net.Snmp.Encoding as SnmpEncoding
import qualified Data.ByteString.Base16 as Base16

main :: IO ()
main = do
  humanFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/human"
  fooFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/foo"
  textListFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/text_list"
  varBindFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/var_bind"
  messageFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/message"
  defaultMain
    [ testGroup "Human" (map (testEncoding "human" encHuman) humanFiles)
    , testGroup "Foo" (map (testEncoding "foo" encFoo) fooFiles)
    , testGroup "Text List" (map (testEncoding "text_list" encTexts) textListFiles)
    , testGroup "VarBind" (map (testEncoding "var_bind" SnmpEncoding.varBind) varBindFiles)
    , testGroup "Message V2" (map (testEncoding "message" SnmpEncoding.messageV2) messageFiles)
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

testEncoding :: Aeson.FromJSON a => String -> AsnEncoding a -> String -> Test
testEncoding name enc dirNum = testCase dirNum $ do
  let path = "sample/" ++ name ++ "/" ++ dirNum ++ "/"
  valueLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.json")
  resultLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.der.base64")
  a <- case Aeson.eitherDecode valueLbs of
    Left err -> fail ("bad json file for model [" ++ name ++ "] test [" ++ dirNum ++ "], error was: " ++ err)
    Right a -> return a
  let encodedLbs = encodeBer enc a
  hexByteString encodedLbs @?= LBC8.unpack (LBC8.filter (not . isSpace) resultLbs)

encHuman :: AsnEncoding Human
encHuman = sequence
  [ required "name" humanName utf8String
  , defaulted "first-words" humanFirstWords utf8String "Hello World"
  , optional "age" humanAge encAge
  ]

encFoo :: AsnEncoding Foo
encFoo = sequence
  [ required "size" fooSize integer
  , required "identifier" fooIdentifier objectIdentifier
  ]

encTexts :: AsnEncoding [Text]
encTexts = sequenceOf utf8String

encAge :: AsnEncoding Age
encAge = choice [AgeBiblical 0, AgeModern 0] $ \x -> case x of
  AgeBiblical n -> option 0 "biblical" n $ tag 0 $ integerRanged 0 1000
  AgeModern n -> option 1 "modern" n $ tag 1 $ integerRanged 0 100

hexByteString :: LB.ByteString -> String
hexByteString = LB.foldr (\w xs -> printf "%02X" w ++ xs) []

deriving instance Aeson.ToJSON ObjectIdentifier
deriving instance Aeson.FromJSON ObjectIdentifier
deriving instance Aeson.ToJSON RequestId
deriving instance Aeson.FromJSON RequestId
deriving instance Aeson.ToJSON ErrorStatus
deriving instance Aeson.FromJSON ErrorStatus
deriving instance Aeson.ToJSON ErrorIndex
deriving instance Aeson.FromJSON ErrorIndex

instance Aeson.ToJSON ByteString where
  toJSON = Aeson.String . Text.pack . ("0x" ++) . hexByteString . LB.fromStrict

instance Aeson.FromJSON ByteString where
  parseJSON = Aeson.withText "ByteString" $ \t -> case Text.unpack t of
    '0' : 'x' : s ->
      let (bs, remaining) = Base16.decode (BC8.pack s) in if BS.length remaining > 0
        then fail "could not parse bytestring"
        else return bs
    _ -> fail "bytestring hex should start with 0x"

$(deriveJSON (myOptions "Age") ''Age)
$(deriveJSON (myOptions "Human") ''Human)
$(deriveJSON (myOptions "Foo") ''Foo)
$(deriveJSON (myOptions "SimpleSyntax") ''SimpleSyntax)
$(deriveJSON (myOptions "ObjectSyntax") ''ObjectSyntax)
$(deriveJSON (myOptions "ApplicationSyntax") ''ApplicationSyntax)
$(deriveJSON (myOptions "BindingResult") ''BindingResult)
$(deriveJSON (myOptions "VarBind") ''VarBind)
$(deriveJSON (myOptions "Pdu") ''Pdu)
$(deriveJSON (myOptions "BulkPdu") ''BulkPdu)
$(deriveJSON (myOptions "Pdus") ''Pdus)
$(deriveJSON (myOptions "MessageV2") ''MessageV2)

