{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

import Control.Monad
import Data.Aeson.TH (deriveJSON)
import Data.ByteString (ByteString)
import Data.Char (isSpace)
import Data.Text (Text)
import Internal (myOptions)
import Language.Asn.Types
import Net.Snmp.Client
import Net.Snmp.Types
import Numeric (readHex)
import Prelude hiding (sequence)
import System.Directory (getDirectoryContents)
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)
import Text.Printf (printf)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LBC8
import qualified Data.List as List
import qualified Data.Text as Text
import qualified Data.Vector as Vector
import qualified GHC.Exts as E
import qualified Language.Asn.Decoding as Decoding
import qualified Language.Asn.Encoding as Encoding
import qualified Net.IPv4 as IPv4
import qualified Net.Snmp.Decoding as SnmpDecoding
import qualified Net.Snmp.Encoding as SnmpEncoding

main :: IO ()
main = do
  humanFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/human"
  fooFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/foo"
  textListFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/text_list"
  varBindFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/var_bind"
  messageFiles <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/message"
  messageV3Files <- List.sort . filter isChildTestDir <$> getDirectoryContents "sample/message_v3"
  defaultMain
    [ testGroup "ASN.1 Codecs"
      [ testGroup "Human" (testEncodingDecoding "human" encHuman decHuman =<< humanFiles)
      , testGroup "Foo" (testEncodingDecoding "foo" encFoo decFoo =<< fooFiles)
      , testGroup "Text List" (testEncodingDecoding "text_list" encTexts decTexts =<< textListFiles)
      , testGroup "VarBind" (testEncodingDecoding "var_bind" SnmpEncoding.varBind SnmpDecoding.varBind =<< varBindFiles)
      , testGroup "Message V2" (testEncodingDecoding "message" SnmpEncoding.messageV2 SnmpDecoding.messageV2 =<< messageFiles)
      -- , testGroup "Message V3" (testEncodingDecoding "message_v3" SnmpEncoding.messageV3 SnmpDecoding.messageV3 =<< messageV3Files)
      ]
    -- , testCase "DES Encryption Isomorphism" testDesEncryption
    , testGroup "SNMP Client"
      [ testCase "V2" $ testSnmpClient (CredentialsConstructV2 (CredentialsV2 "public"))
      , testCase "V3 NoAuthNoPriv" 
          $ testSnmpClient 
          $ CredentialsConstructV3 
          $ CredentialsV3 NoAuthNoPriv "" "usr_NoAuthNoPriv"
      , testCase "V3 AuthNoPriv MD5" $ testSnmpClient $ authCreds
          AuthTypeMd5 "usr_MD5AuthNoPriv" "password_MD5AuthNoPriv"
      , testCase "V3 AuthNoPriv SHA" $ testSnmpClient $ authCreds
          AuthTypeSha "usr_SHAAuthNoPriv" "password_SHAAuthNoPriv"
      , testCase "V3 AuthPriv MD5 DES" $ testSnmpClient $ privCreds
          AuthTypeMd5 PrivTypeDes "usr_MD5AuthDESPriv" "password_MD5AuthDESPriv" "encryption_MD5AuthDESPriv" 
      , testCase "V3 AuthPriv SHA DES" $ testSnmpClient $ privCreds
          AuthTypeSha PrivTypeDes "usr_SHAAuthDESPriv" "password_SHAAuthDESPriv" "encryption_SHAAuthDESPriv" 
      , testCase "V3 AuthPriv MD5 AES" $ testSnmpClient $ privCreds
          AuthTypeMd5 PrivTypeAes "usr_MD5AuthAESPriv" "password_MD5AuthAESPriv" "encryption_MD5AuthAESPriv" 
      , testCase "V3 AuthPriv SHA AES" $ testSnmpClient $ privCreds
          AuthTypeSha PrivTypeAes "usr_SHAAuthAESPriv" "password_SHAAuthAESPriv" "encryption_SHAAuthAESPriv" 
      ]
    ]

-- This does not check for correctness in the case of concurrent
-- SNMP requests.
testSnmpClient :: Credentials -> IO ()
testSnmpClient creds = do
  s <- openSession (Config 1 2000000 1)
  let ctx = Context s (Destination (IPv4.ipv4 127 0 0 1) 161) creds
  _ <- get ctx (ObjectIdentifier (E.fromList [1,3,6,1,2,1,1,1,0]))
  closeSession s

authCreds :: AuthType -> ByteString -> ByteString -> Credentials
authCreds typ user pass = CredentialsConstructV3
  $ CredentialsV3
    (AuthNoPriv (AuthParameters typ pass))
    ""
    user

privCreds :: AuthType -> PrivType -> ByteString -> ByteString -> ByteString -> Credentials
privCreds authType privType user authPass privPass = CredentialsConstructV3
  $ CredentialsV3
    (AuthPriv 
      (AuthParameters authType authPass)
      (PrivParameters privType privPass)
    )
    ""
    user

testDesEncryption :: IO ()
testDesEncryption = do
  let plaintext = "abcdefghijklmnopqrstuvwxyz"
      key = SnmpEncoding.passwordToKey AuthTypeMd5 "weakpassword" (EngineId "foobar")
      (encrypted,salt) = SnmpEncoding.desEncrypt key 1 2 plaintext
      restored = SnmpEncoding.desDecrypt key salt encrypted
  restored @?= Just plaintext

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