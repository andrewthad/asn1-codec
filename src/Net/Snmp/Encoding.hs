{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TupleSections #-}

module Net.Snmp.Encoding where

import Prelude hiding (sequence,null)
import Language.Asn.Encoding
import Language.Asn.Types
import Net.Snmp.Types
import Data.Coerce (coerce)
import Data.ByteString (ByteString)
import Data.Functor.Contravariant
import Data.Bifunctor
import Data.Word
import Data.Int
import Data.Bits
import Data.Monoid
import Data.Maybe
import qualified Crypto.Cipher.AES as Priv
import qualified Crypto.Cipher.DES as Priv
import qualified Crypto.Cipher.Types as Priv
import qualified Crypto.Data.Padding as Pad
import qualified Crypto.Error as Priv
import qualified Data.ByteString as B
import qualified Data.List as List
import qualified Crypto.MAC.HMAC as HMAC
import qualified Language.Asn.Encoding as AsnEncoding
import qualified Data.ByteArray as BA
import qualified Crypto.Hash as Hash
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LB
import qualified Data.Vector as Vector
import qualified Data.ByteString.Builder as Builder

messageV2 :: AsnEncoding MessageV2
messageV2 = sequence
  [ required "version" (const 1) integer
  , required "community" messageV2CommunityString octetString
  , required "data" messageV2Data pdus
  ]

simpleSyntax :: AsnEncoding SimpleSyntax
simpleSyntax = choice
  [ SimpleSyntaxInteger 0
  , SimpleSyntaxString ByteString.empty
  , SimpleSyntaxObjectId defaultObjectIdentifier
  ] $ \x -> case x of
  SimpleSyntaxInteger n -> option 0 "integer-value" n int32
  SimpleSyntaxString bs -> option 1 "string-value" bs octetString
  SimpleSyntaxObjectId oid -> option 2 "objectID-value" oid objectIdentifier

applicationSyntax :: AsnEncoding ApplicationSyntax
applicationSyntax = choice
  [ ApplicationSyntaxIpAddress 0
  , ApplicationSyntaxCounter 0
  , ApplicationSyntaxTimeTicks 0
  , ApplicationSyntaxArbitrary ByteString.empty
  , ApplicationSyntaxBigCounter 0
  , ApplicationSyntaxUnsignedInteger 0
  ] $ \x -> case x of
  ApplicationSyntaxIpAddress n -> option 0 "ipAddress-value" n
    $ tag Application 0 Implicit octetStringWord32
  ApplicationSyntaxCounter n -> option 1 "counter-value" n
    $ tag Application 1 Implicit word32
  ApplicationSyntaxTimeTicks n -> option 2 "timeticks-value" n
    $ tag Application 3 Implicit word32
  ApplicationSyntaxArbitrary n -> option 3 "arbitrary-value" n
    $ tag Application 4 Implicit octetString
  ApplicationSyntaxBigCounter n -> option 4 "big-counter-value" n
    $ tag Application 6 Implicit word64
  ApplicationSyntaxUnsignedInteger n -> option 5 "unsigned-integer-value" n
    $ tag Application 2 Implicit word32

objectSyntax :: AsnEncoding ObjectSyntax
objectSyntax = choice
  [ ObjectSyntaxSimple (SimpleSyntaxInteger 0)
  , ObjectSyntaxApplication (ApplicationSyntaxCounter 0)
  ] $ \x -> case x of
  ObjectSyntaxSimple v -> option 0 "simple" v simpleSyntax
  ObjectSyntaxApplication v -> option 1 "application-wide" v applicationSyntax

bindingResult :: AsnEncoding BindingResult
bindingResult = choice
  [ BindingResultValue (ObjectSyntaxSimple (SimpleSyntaxInteger 0))
  , BindingResultUnspecified
  , BindingResultNoSuchObject
  , BindingResultNoSuchInstance
  , BindingResultEndOfMibView
  ] $ \x -> case x of
  BindingResultValue obj -> option 0 "value" obj objectSyntax
  BindingResultUnspecified -> option 1 "unSpecified" () null
  BindingResultNoSuchObject -> option 2 "noSuchObject" () $ implicitTag 0 null
  BindingResultNoSuchInstance -> option 3 "noSuchInstance" () $ implicitTag 1 null
  BindingResultEndOfMibView -> option 4 "endOfMibView" () $ implicitTag 2 null

varBind :: AsnEncoding VarBind
varBind = sequence
  [ required "name" varBindName objectIdentifier
    -- result is not actually named in the RFC
  , required "result" varBindResult bindingResult
  ]

pdu :: AsnEncoding Pdu
pdu = sequence
  [ required "request-id" pduRequestId (coerce int)
  , required "error-status" pduErrorStatus (coerce integer)
  , required "error-index" pduErrorIndex (coerce int32)
  , required "variable-bindings" pduVariableBindings (sequenceOf varBind)
  ]

bulkPdu :: AsnEncoding BulkPdu
bulkPdu = sequence
  [ required "request-id" bulkPduRequestId (coerce int)
  , required "non-repeaters" bulkPduNonRepeaters int32
  , required "max-repetitions" bulkPduMaxRepetitions int32
  , required "variable-bindings" bulkPduVariableBindings (sequenceOf varBind)
  ]

pdus :: AsnEncoding Pdus
pdus = choice
  [ PdusGetRequest defaultPdu
  , PdusGetNextRequest defaultPdu
  , PdusGetBulkRequest (BulkPdu (RequestId 0) 0 0 Vector.empty)
  , PdusResponse defaultPdu
  , PdusSetRequest defaultPdu
  , PdusInformRequest defaultPdu
  , PdusSnmpTrap defaultPdu
  , PdusReport defaultPdu
  ] $ \x -> case x of
  PdusGetRequest p -> option 0 "get-request" p $ implicitTag 0 pdu
  PdusGetNextRequest p -> option 1 "get-next-request" p $ implicitTag 1 pdu
  PdusGetBulkRequest p -> option 2 "get-bulk-request" p $ implicitTag 5 bulkPdu
  PdusResponse p -> option 3 "response" p $ implicitTag 2 pdu
  PdusSetRequest p -> option 4 "set-request" p $ implicitTag 3 pdu
  PdusInformRequest p -> option 5 "inform-request" p $ implicitTag 6 pdu
  PdusSnmpTrap p -> option 6 "snmpV2-trap" p $ implicitTag 7 pdu
  PdusReport p -> option 7 "report" p $ implicitTag 8 pdu

defaultObjectIdentifier :: ObjectIdentifier
defaultObjectIdentifier = ObjectIdentifier (Vector.fromList [1,3,6])

defaultPdu :: Pdu
defaultPdu = Pdu (RequestId 0) (ErrorStatus 0) (ErrorIndex 0) Vector.empty

defaultUsm :: Usm
defaultUsm = Usm ByteString.empty 0 0 ByteString.empty

messageV3 :: AsnEncoding ((Crypto,AesSalt),MessageV3)
messageV3 = contramap (\(c,m) -> ((c,Just m),m)) internalMessageV3

internalMessageV3 :: AsnEncoding (((Crypto,AesSalt),Maybe MessageV3),MessageV3)
internalMessageV3 = sequence
  [ required "msgVersion" (const 3) integer
  , required "msgGlobalData" (\(((c,_),_),msg) -> (c,messageV3GlobalData msg)) headerData
  , required "msgSecurityParameters"
      (\(pair,msg) -> LB.toStrict (AsnEncoding.der usm (pair,messageV3SecurityParameters msg))) octetString
          -- $ AsnEncoding.der internalMessageV3 ((c,Nothing),msg)
  , required "msgData" (\((c,_),msg) -> ((c,messageV3SecurityParameters msg),messageV3Data msg)) scopedPduDataEncoding
  ]

headerData :: AsnEncoding (Crypto,HeaderData)
headerData = sequence
  [ required "msgID" (headerDataId . snd) (coerce int)
  , required "msgMaxSize" (headerDataMaxSize . snd) int32
  , required "msgFlags" (ByteString.singleton . cryptoFlags . fst) octetString
  , required "msgSecurityModel" (const 3) integer
  ]

scopedPduDataEncoding :: AsnEncoding (((Crypto,AesSalt),Usm),ScopedPdu)
scopedPduDataEncoding = choice
  [ (((NoAuthNoPriv, AesSalt 0),defaultUsm), defaultScopedPdu)
  , (((AuthPriv defaultAuthParams defaultPrivParams, AesSalt 0),defaultUsm), defaultScopedPdu)
  ] $ \(((c,theSalt),u),spdu) -> case c of
  AuthPriv (AuthParameters authType authKey) (PrivParameters privType privPass) ->
    option 1 "encryptedPDU" spdu $ contramap
    (\spdu -> case privType of
        PrivTypeDes -> desEncrypt
          (passwordToKey authType authKey (usmEngineId u))
          (usmEngineBoots u)
          (usmEngineTime u)
          (LB.toStrict (AsnEncoding.der scopedPdu spdu))
        PrivTypeAes -> aesEncrypt
          (passwordToKey authType authKey (usmEngineId u))
          (usmEngineBoots u)
          (usmEngineTime u)
          theSalt
          (LB.toStrict (AsnEncoding.der scopedPdu spdu))
    )
    octetString
  _ -> option 0 "plaintext" spdu scopedPdu

scopedPdu :: AsnEncoding ScopedPdu
scopedPdu = sequence
  [ required "contextEngineID" scopedPduContextEngineId octetString
  , required "contextName" scopedPduContextName octetString
  , required "data" scopedPduData pdus
  ]

usm :: AsnEncoding (((Crypto,AesSalt),Maybe MessageV3),Usm)
usm = sequence
  [ required "msgAuthoritativeEngineID" (usmEngineId . snd) octetString
  , required "msgAuthoritativeEngineBoots" (usmEngineBoots . snd) int32
  , required "msgAuthoritativeEngineTime" (usmEngineTime . snd) int32
  , required "msgUserName" (usmUserName . snd) octetString
  , required "msgAuthenticationParameters" (\(((c,s),mmsg),u) -> case cryptoAuth c of
      Nothing -> ByteString.empty
      Just (AuthParameters authType authKey) -> case mmsg of
        Nothing -> ByteString.replicate 12 0x00
        Just msg -> id
          $ ByteString.take 12
          $ hmacEncodedMessage authType (passwordToKey authType authKey (usmEngineId u))
          $ LB.toStrict
          $ AsnEncoding.der internalMessageV3 (((c,s),Nothing),msg)
    ) octetString
  , required "msgPrivacyParameters" (\(((c,AesSalt s),_),u) -> case cryptoPriv c of
      Nothing -> ByteString.empty
      Just (PrivParameters privType _) -> case privType of
        PrivTypeDes -> toSalt (usmEngineBoots u) (usmEngineTime u)
        PrivTypeAes -> wToBs s
    ) octetString
  ]

-- hashEncodedMessage :: AuthType -> ByteString -> ByteString
-- hashEncodedMessage x bs = case x of
--   AuthTypeMd5 -> BA.convert (Hash.hash bs :: Hash.Digest Hash.MD5)
--   AuthTypeSha -> BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA1)

hmacEncodedMessage :: AuthType -> ByteString -> ByteString -> ByteString
hmacEncodedMessage x key bs = case x of
  AuthTypeMd5 -> BA.convert (HMAC.hmac key bs :: HMAC.HMAC Hash.MD5)
  AuthTypeSha -> BA.convert (HMAC.hmac key bs :: HMAC.HMAC Hash.SHA1)

hash :: AuthType -> ByteString -> ByteString
hash AuthTypeMd5 = BA.convert . (Hash.hash :: ByteString -> Hash.Digest Hash.MD5)
hash AuthTypeSha = BA.convert . (Hash.hash :: ByteString -> Hash.Digest Hash.SHA1)

hashlazy :: AuthType -> LB.ByteString -> ByteString
hashlazy AuthTypeMd5 = BA.convert . (Hash.hashlazy :: LB.ByteString -> Hash.Digest Hash.MD5)
hashlazy AuthTypeSha = BA.convert . (Hash.hashlazy :: LB.ByteString -> Hash.Digest Hash.SHA1)

passwordToKey :: AuthType -> ByteString -> ByteString -> ByteString
passwordToKey at pass eid = hash at (authKey <> eid <> authKey)
  where
    mkAuthKey = hashlazy at . LB.take 1048576 . LB.fromChunks . List.repeat
    !authKey = mkAuthKey pass
{-# INLINE passwordToKey #-}

defaultAuthParams :: AuthParameters
defaultAuthParams = AuthParameters AuthTypeSha ByteString.empty

defaultPrivParams :: PrivParameters
defaultPrivParams = PrivParameters PrivTypeDes ByteString.empty

defaultScopedPdu :: ScopedPdu
defaultScopedPdu = ScopedPdu ByteString.empty ByteString.empty (PdusGetRequest defaultPdu)

-- type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString

desEncrypt :: ByteString -> Int32 -> Int32 -> ByteString -> Encrypted
desEncrypt privKey eb et =
    Priv.cbcEncrypt cipher iv . Pad.pad Pad.PKCS5
  where
    preIV = B.drop 8 (B.take 16 privKey)
    salt = toSalt eb et
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

aesEncrypt :: ByteString -> Int32 -> Int32 -> AesSalt -> Raw -> Encrypted
aesEncrypt privKey eb et (AesSalt rcounter) =
    Priv.cfbEncrypt cipher iv
  where
    salt = wToBs rcounter
    iv :: Priv.IV Priv.AES128
    !iv = fromJust $ Priv.makeIV (toSalt eb et <> salt)
    !cipher = mkCipher (B.take 16 privKey)


wToBs :: Word64 -> ByteString
wToBs x = B.pack
  [ fromIntegral (x `shiftR` 56 .&. 0xff)
  , fromIntegral (x `shiftR` 48 .&. 0xff)
  , fromIntegral (x `shiftR` 40 .&. 0xff)
  , fromIntegral (x `shiftR` 32 .&. 0xff)
  , fromIntegral (x `shiftR` 24 .&. 0xff)
  , fromIntegral (x `shiftR` 16 .&. 0xff)
  , fromIntegral (x `shiftR` 8 .&. 0xff)
  , fromIntegral (x `shiftR` 0 .&. 0xff)
  ]

toSalt :: Int32 -> Int32 -> ByteString
toSalt x y = B.pack
  [ fromIntegral (x `shiftR` 24 .&. 0xff)
  , fromIntegral (x `shiftR` 16 .&. 0xff)
  , fromIntegral (x `shiftR`  8 .&. 0xff)
  , fromIntegral (x `shiftR`  0 .&. 0xff)
  , fromIntegral (y `shiftR` 24 .&. 0xff)
  , fromIntegral (y `shiftR` 16 .&. 0xff)
  , fromIntegral (y `shiftR`  8 .&. 0xff)
  , fromIntegral (y `shiftR`  0 .&. 0xff)
  ]

mkCipher :: (Priv.Cipher c) => ByteString -> c
mkCipher = (\(Priv.CryptoPassed x) -> x) . Priv.cipherInit
{-# INLINE mkCipher #-}

