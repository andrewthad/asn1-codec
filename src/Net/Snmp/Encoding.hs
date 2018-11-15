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
import qualified GHC.Exts as E
import qualified Crypto.Cipher.AES as Priv
import qualified Crypto.Cipher.DES as Priv
import qualified Crypto.Cipher.Types as Priv
-- import qualified Crypto.Cipher.DES as Priv
-- import qualified Crypto.Cipher.AES as Priv

import qualified Crypto.Data.Padding as Pad
import qualified Crypto.Error as Priv
import qualified Data.ByteString as B
import qualified Data.List as List
import qualified Crypto.MAC.HMAC as HMAC
-- import qualified Crypto.Hash.MD5 as Md5
-- import qualified Crypto.Hash.SHA1 as Sha


import qualified Language.Asn.Encoding as AsnEncoding
import qualified Data.ByteArray as BA
import qualified Crypto.Hash as Hash
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy as BL
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

trapPdu :: AsnEncoding TrapPdu
trapPdu = error "Net.Snmp.Encoding.trapPdu: not yet implemented"

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
  , PdusSnmpTrap (TrapPdu defaultObjectIdentifier 0 GenericTrapColdStart 0 0 [])
  , PdusReport defaultPdu
  ] $ \x -> case x of
  PdusGetRequest p -> option 0 "get-request" p $ implicitTag 0 pdu
  PdusGetNextRequest p -> option 1 "get-next-request" p $ implicitTag 1 pdu
  PdusGetBulkRequest p -> option 2 "get-bulk-request" p $ implicitTag 5 bulkPdu
  PdusResponse p -> option 3 "response" p $ implicitTag 2 pdu
  PdusSetRequest p -> option 4 "set-request" p $ implicitTag 3 pdu
  PdusInformRequest p -> option 5 "inform-request" p $ implicitTag 6 pdu
  PdusSnmpTrap p -> option 6 "snmpV2-trap" p $ implicitTag 4 trapPdu
  PdusReport p -> option 7 "report" p $ implicitTag 8 pdu

defaultObjectIdentifier :: ObjectIdentifier
defaultObjectIdentifier = ObjectIdentifier (E.fromList [1,3,6])

defaultPdu :: Pdu
defaultPdu = Pdu (RequestId 0) (ErrorStatus 0) (ErrorIndex 0) Vector.empty

defaultUsm :: Usm
defaultUsm = Usm defaultEngineId 0 0 ByteString.empty ByteString.empty ByteString.empty

-- messageV3 :: AsnEncoding ((Crypto,AesSalt),MessageV3)
-- messageV3 = contramap (\(c,m) -> ((c,Just m),m)) internalMessageV3

messageV3 :: AsnEncoding MessageV3
messageV3 = sequence
  [ required "msgVersion" (const 3) integer
  , required "msgGlobalData" messageV3GlobalData headerData
  , required "msgSecurityParameters" 
      (\msg -> LB.toStrict (AsnEncoding.der usm (messageV3SecurityParameters msg)))
      octetString
  , required "msgData" messageV3Data scopedPduDataEncoding
  ]

headerData :: AsnEncoding HeaderData
headerData = sequence
  [ required "msgID" headerDataId (coerce int)
  , required "msgMaxSize" headerDataMaxSize int32
  , required "msgFlags" headerDataFlags octetStringWord8
  , required "msgSecurityModel" (const 3) integer
  ]

scopedPduDataEncoding :: AsnEncoding ScopedPduData
scopedPduDataEncoding = choice
  [ ScopedPduDataPlaintext defaultScopedPdu
  , ScopedPduDataEncrypted ByteString.empty
  ] $ \s -> case s of
  ScopedPduDataPlaintext spdu -> option 0 "plaintext" spdu scopedPdu
  ScopedPduDataEncrypted bs -> option 1 "encryptedPDU" bs octetString

-- scopedPduDataEncoding :: AsnEncoding (((Crypto,AesSalt),Usm),ScopedPdu)
-- scopedPduDataEncoding = choice
--   [ (((NoAuthNoPriv, AesSalt 0),defaultUsm), defaultScopedPdu)
--   , (((AuthPriv defaultAuthParams defaultPrivParams, AesSalt 0),defaultUsm), defaultScopedPdu)
--   ] $ \(((c,theSalt),u),spdu) -> case c of
--   AuthPriv (AuthParameters authType authKey) (PrivParameters privType privPass) ->
--     option 1 "encryptedPDU" spdu $ contramap
--     (\spdu -> case privType of
--         PrivTypeDes -> desEncrypt
--           (passwordToKey authType authKey (usmEngineId u))
--           (usmEngineBoots u)
--           (usmEngineTime u)
--           (LB.toStrict (AsnEncoding.der scopedPdu spdu))
--         PrivTypeAes -> aesEncrypt
--           (passwordToKey authType authKey (usmEngineId u))
--           (usmEngineBoots u)
--           (usmEngineTime u)
--           theSalt
--           (LB.toStrict (AsnEncoding.der scopedPdu spdu))
--     )
--     octetString
--   _ -> option 0 "plaintext" spdu scopedPdu

scopedPdu :: AsnEncoding ScopedPdu
scopedPdu = sequence
  [ required "contextEngineID" scopedPduContextEngineId (coerce octetString)
  , required "contextName" scopedPduContextName octetString
  , required "data" scopedPduData pdus
  ]

usm :: AsnEncoding Usm
usm = sequence
  [ required "msgAuthoritativeEngineID" usmAuthoritativeEngineId (coerce octetString)
  , required "msgAuthoritativeEngineBoots" usmAuthoritativeEngineBoots int32
  , required "msgAuthoritativeEngineTime" usmAuthoritativeEngineTime int32
  , required "msgUserName" usmUserName octetString
  , required "msgAuthenticationParameters" usmAuthenticationParameters octetString
  , required "msgPrivacyParameters" usmPrivacyParameters octetString
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

passwordToKey :: AuthType -> ByteString -> EngineId -> ByteString
passwordToKey at pass (EngineId eid) = 
  hash at (authKey <> eid <> authKey)
  where
  mkAuthKey = hashlazy at . LB.take 1048576 . LB.fromChunks . List.repeat
  !authKey = mkAuthKey pass

defaultAuthParams :: AuthParameters
defaultAuthParams = AuthParameters AuthTypeSha ByteString.empty

defaultPrivParams :: PrivParameters
defaultPrivParams = PrivParameters PrivTypeDes ByteString.empty

defaultScopedPdu :: ScopedPdu
defaultScopedPdu = ScopedPdu defaultEngineId ByteString.empty (PdusGetRequest defaultPdu)

defaultEngineId :: EngineId
defaultEngineId = EngineId ByteString.empty

-- type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString

desEncrypt :: 
     ByteString 
  -> Int32 
  -> Int32 
  -> ByteString 
  -> (Encrypted,ByteString)
desEncrypt privKey eb et =
    (,salt) . Priv.cbcEncrypt cipher iv . Pad.pad Pad.PKCS5
  where
    preIV = B.drop 8 (B.take 16 privKey)
    salt = toSalt eb et
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

desDecrypt :: ByteString -> ByteString -> Encrypted -> Maybe Raw
desDecrypt privKey salt =
    Just . stripBS . Priv.cbcDecrypt cipher iv
  where
    preIV = B.drop 8 (B.take 16 privKey)
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

aesDecrypt :: ByteString -> ByteString -> Int32 -> Int32 -> Encrypted -> Maybe Raw
aesDecrypt privKey salt eb et =
    Just . stripBS . Priv.cfbDecrypt cipher iv
  where
    iv :: Priv.IV Priv.AES128
    !iv = fromJust $ Priv.makeIV (toSalt eb et <> salt)
    !cipher = mkCipher (B.take 16 privKey)

stripBS :: ByteString -> ByteString
stripBS bs =
    let bs' = B.drop 1 bs
        l1 = fromIntegral (B.head bs')
    in if testBit l1 7
        then case clearBit l1 7 of
                  0   -> error "something bad happened while decrypting"
                  len ->
                    let size = uintbs (B.take len (B.drop 1 bs'))
                    in B.take (size + len + 2) bs
        else B.take (l1 + 2) bs
  where
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl' (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

aesEncrypt :: ByteString -> Int32 -> Int32 -> AesSalt -> Raw -> (Encrypted,ByteString)
aesEncrypt privKey eb et (AesSalt rcounter) =
  (,salt) . Priv.cfbEncrypt cipher iv
  where
  salt = wToBs rcounter
  iv :: Priv.IV Priv.AES128
  !iv = unJust $ Priv.makeIV (toSalt eb et <> salt)
  !cipher = mkCipher (B.take 16 privKey)
  unJust x = case x of
    Nothing -> error "Net.Snmp.Encoding: aesEncrypt: bad salt"
    Just a -> a
   
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

mkSign :: AuthType -> ByteString -> ByteString -> ByteString
mkSign at key = B.take 12 . hmacEncodedMessage at key
{-# INLINE mkSign #-}

-- mkSign :: AuthType -> ByteString -> ByteString -> ByteString
-- mkSign = error "mkSign: write this"

checkSign :: AuthType -> ByteString -> MessageV3 -> Maybe (ByteString,ByteString)
checkSign at key msg = if expected == actual
  then Nothing
  else Just (expected,actual)
  where 
  raw = LB.toStrict (AsnEncoding.der messageV3 (resetAuthParams msg))
  expected = mkSign at key raw
  actual = usmAuthenticationParameters (messageV3SecurityParameters msg)

resetAuthParams :: MessageV3 -> MessageV3
resetAuthParams m = m 
  { messageV3SecurityParameters = (messageV3SecurityParameters m)
    { usmAuthenticationParameters = ByteString.replicate 12 0x00
    }
  }

