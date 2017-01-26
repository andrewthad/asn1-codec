{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

import Prelude hiding (sequence)
import Language.Asn.Types
import qualified Language.Asn.Encoding as Encoding
import qualified Language.Asn.Decoding as Decoding
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
import Control.Monad
import qualified Data.Text as Text
import qualified Data.List as List
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LBC8
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString as BS
import qualified Net.Snmp.Encoding as SnmpEncoding
import qualified Net.Snmp.Decoding as SnmpDecoding
import qualified Data.ByteString.Base16 as Base16

main :: IO ()
main = do
  humanFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/human"
  fooFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/foo"
  textListFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/text_list"
  varBindFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/var_bind"
  messageFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/message"
  messageV3Files <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/message_v3"
  defaultMain
    [ testGroup "Human" (testEncodingDecoding "human" encHuman decHuman =<< humanFiles)
    , testGroup "Foo" (testEncodingDecoding "foo" encFoo decFoo =<< fooFiles)
    , testGroup "Text List" (testEncodingDecoding "text_list" encTexts decTexts =<< textListFiles)
    , testGroup "VarBind" (testEncodingDecoding "var_bind" SnmpEncoding.varBind SnmpDecoding.varBind =<< varBindFiles)
    , testGroup "Message V2" (testEncodingDecoding "message" SnmpEncoding.messageV2 SnmpDecoding.messageV2 =<< messageFiles)
    -- , testGroup "Message V3" (testEncodingDecoding "message_v3" SnmpEncoding.messageV3 SnmpDecoding.messageV3 =<< messageV3Files)
    ]

isChildTestDir :: String -> Bool
isChildTestDir s = s /= "." && s /= ".." && s /= "definition.asn1"

data Human = Human
  { humanName :: Text
  , humanFirstWords :: Text
  , humanAge :: Maybe Age
  } deriving (Eq,Show)

data Age = AgeBiblical Integer | AgeModern Integer
  deriving (Eq,Show)

data Foo = Foo
  { fooSize :: Integer
  , fooIdentifier :: ObjectIdentifier
  } deriving (Eq,Show)

testEncoding :: Aeson.FromJSON a => String -> AsnEncoding a -> String -> Test
testEncoding name enc dirNum = testCase dirNum $ do
  let path = "sample/" ++ name ++ "/" ++ dirNum ++ "/"
  valueLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.json")
  resultLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.der.base64")
  a <- case Aeson.eitherDecode valueLbs of
    Left err -> fail ("bad json file for model [" ++ name ++ "] test [" ++ dirNum ++ "], error was: " ++ err)
    Right a -> return a
  let encodedLbs = Encoding.der enc a
  hexByteString encodedLbs @?= LBC8.unpack (LBC8.filter (not . isSpace) resultLbs)

testEncodingDecoding :: (Aeson.FromJSON a, Eq a, Show a) => String -> AsnEncoding a -> AsnDecoding a -> String -> [Test]
testEncodingDecoding name enc dec dirNum =
  let load = do
        let path = "sample/" ++ name ++ "/" ++ dirNum ++ "/"
        valueLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.json")
        resultLbs <- fmap LB.fromStrict $ BS.readFile (path ++ "value.der.base64")
        a <- case Aeson.eitherDecode valueLbs of
          Left err -> fail ("bad json file for model [" ++ name ++ "] test [" ++ dirNum ++ "], error was: " ++ err)
          Right a -> return a
        return (resultLbs,a)
   in [ testCase (dirNum ++ " encoding") $ do
          (resultLbs, a) <- load
          let encodedLbs = Encoding.der enc a
          hexByteString encodedLbs @?= LBC8.unpack (LBC8.filter (not . isSpace) resultLbs)
      , testCase (dirNum ++ " decoding") $ do
          (resultLbs, expectedA) <- load
          let (bs, remaining) = Base16.decode (BC8.filter (not . isSpace) $ LB.toStrict resultLbs)
          when (BS.length remaining > 0) $ fail "provided hexadecimal in DER file was invalid hex"
          foundA <- case Decoding.ber dec bs of
            Left err -> fail $ "decoding ASN.1 BER file failed with: " ++ show err
            Right foundA -> return foundA
          foundA @?= expectedA
      ]

encHuman :: AsnEncoding Human
encHuman = Encoding.sequence
  [ Encoding.required "name" humanName Encoding.utf8String
  , Encoding.defaulted "first-words" humanFirstWords Encoding.utf8String "Hello World"
  , Encoding.optional "age" humanAge encAge
  ]

decHuman :: AsnDecoding Human
decHuman = Decoding.sequence $ Human
  <$> Decoding.required "name" Decoding.utf8String
  <*> Decoding.defaulted "first-words" Decoding.utf8String "Hello World"
  <*> Decoding.optional "age" decAge

decAge :: AsnDecoding Age
decAge = Decoding.choice
  [ fmap AgeBiblical $ Decoding.option "biblical" $ Decoding.tag ContextSpecific 0 Explicit $ Decoding.integerRanged 0 1000
  , fmap AgeModern $ Decoding.option "modern" $ Decoding.tag ContextSpecific 1 Explicit $ Decoding.integerRanged 0 100
  ]

encFoo :: AsnEncoding Foo
encFoo = Encoding.sequence
  [ Encoding.required "size" fooSize Encoding.integer
  , Encoding.required "identifier" fooIdentifier Encoding.objectIdentifier
  ]

decFoo :: AsnDecoding Foo
decFoo = Decoding.sequence $ Foo
  <$> Decoding.required "size" Decoding.integer
  <*> Decoding.required "identifier" Decoding.objectIdentifier

encTexts :: AsnEncoding [Text]
encTexts = Encoding.sequenceOf Encoding.utf8String

decTexts :: AsnDecoding [Text]
decTexts = Decoding.sequenceOf Decoding.utf8String

encAge :: AsnEncoding Age
encAge = Encoding.choice [AgeBiblical 0, AgeModern 0] $ \x -> case x of
  AgeBiblical n -> Encoding.option 0 "biblical" n $ Encoding.tag ContextSpecific 0 Explicit $ Encoding.integerRanged 0 1000
  AgeModern n -> Encoding.option 1 "modern" n $ Encoding.tag ContextSpecific 1 Explicit $ Encoding.integerRanged 0 100

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
deriving instance Aeson.ToJSON EngineId
deriving instance Aeson.FromJSON EngineId

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
$(deriveJSON (myOptions "HeaderData") ''HeaderData)
$(deriveJSON (myOptions "ScopedPdu") ''ScopedPdu)
$(deriveJSON (myOptions "ScopedPduData") ''ScopedPduData)
$(deriveJSON (myOptions "Usm") ''Usm)
$(deriveJSON (myOptions "MessageV2") ''MessageV2)
$(deriveJSON (myOptions "MessageV3") ''MessageV3)

