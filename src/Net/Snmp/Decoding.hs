{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

module Net.Snmp.Decoding where

import Prelude hiding (sequence,null)
import Language.Asn.Decoding
import Language.Asn.Types
import Net.Snmp.Types
import Data.Coerce (coerce)
import Data.ByteString (ByteString)
import Text.Printf (printf)
import Data.Bifunctor
import Data.Bits
import Data.Monoid
import Data.Maybe
import Data.Int
import qualified Data.List as List
import qualified Crypto.MAC.HMAC as HMAC
import qualified Data.ByteArray as BA
import qualified Crypto.Hash as Hash
import qualified Data.ByteString as B
import qualified Crypto.Cipher.AES as Priv
import qualified Crypto.Cipher.DES as Priv
import qualified Crypto.Cipher.Types as Priv
import qualified Crypto.Data.Padding as Pad
import qualified Crypto.Error as Priv
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector
import qualified Net.Snmp.Encoding as E
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LB
import qualified Language.Asn.Decoding as AsnDecoding

messageV2 :: AsnDecoding MessageV2
messageV2 = sequence $ MessageV2
  <$  required "version" integer -- make this actually demand that it's 1
  <*> required "community" octetString
  <*> required "data" pdus

simpleSyntax :: AsnDecoding SimpleSyntax
simpleSyntax = choice
  [ fmap SimpleSyntaxInteger $ option "integer-value" int32
  , fmap SimpleSyntaxString $ option "string-value" octetString
  , fmap SimpleSyntaxObjectId $ option "objectID-value" objectIdentifier
  ]

applicationSyntax :: AsnDecoding ApplicationSyntax
applicationSyntax = choice
  [ fmap ApplicationSyntaxIpAddress
      $ option "ipAddress-value" $ tag Application 0 Implicit octetStringWord32
  , fmap ApplicationSyntaxCounter
      $ option "counter-value" $ tag Application 1 Implicit word32
  , fmap ApplicationSyntaxTimeTicks
      $ option "timeticks-value" $ tag Application 3 Implicit word32
  , fmap ApplicationSyntaxArbitrary
      $ option "arbitrary-value" $ tag Application 4 Implicit octetString
  , fmap ApplicationSyntaxBigCounter
      $ option "big-counter-value" $ tag Application 6 Implicit word64
  , fmap ApplicationSyntaxUnsignedInteger
      $ option "unsigned-integer-value" $ tag Application 2 Implicit word32
  ]

objectSyntax :: AsnDecoding ObjectSyntax
objectSyntax = choice
  [ fmap ObjectSyntaxSimple $ option "simple" simpleSyntax
  , fmap ObjectSyntaxApplication $ option "application-wide" applicationSyntax
  ]

bindingResult :: AsnDecoding BindingResult
bindingResult = choice
  [ BindingResultValue <$> option "value" objectSyntax
  , BindingResultUnspecified <$ option "unSpecified" null
  , BindingResultNoSuchObject <$ option "noSuchObject" (tag ContextSpecific 0 Implicit null)
  , BindingResultNoSuchInstance <$ option "noSuchInstance" (tag ContextSpecific 1 Implicit null)
  , BindingResultEndOfMibView <$ option "endOfMibView" (tag ContextSpecific 2 Implicit null)
  ]

varBind :: AsnDecoding VarBind
varBind = sequence $ VarBind
  <$> required "name" objectIdentifier
  -- result is not actually named in the RFC
  <*> required "result" bindingResult

pdu :: AsnDecoding Pdu
pdu = sequence $ Pdu
  <$> required "request-id" (coerce int)
  <*> required "error-status" (coerce integer)
  <*> required "error-index" (coerce int32)
  <*> required "variable-bindings" (fmap Vector.fromList $ sequenceOf varBind)

bulkPdu :: AsnDecoding BulkPdu
bulkPdu = sequence $ BulkPdu
  <$> required "request-id" (coerce int)
  <*> required "non-repeaters" int32
  <*> required "max-repetitions" int32
  <*> required "variable-bindings" (fmap Vector.fromList $ sequenceOf varBind)

pdus :: AsnDecoding Pdus
pdus = choice
  [ PdusGetRequest <$> option "get-request" (tag ContextSpecific 0 Implicit pdu)
  , PdusGetNextRequest <$> option "get-next-request" (tag ContextSpecific 1 Implicit pdu)
  , PdusGetBulkRequest <$> option "get-bulk-request" (tag ContextSpecific 5 Implicit bulkPdu)
  , PdusResponse <$> option "response" (tag ContextSpecific 2 Implicit pdu)
  , PdusSetRequest <$> option "set-request" (tag ContextSpecific 3 Implicit pdu)
  , PdusInformRequest <$> option "inform-request" (tag ContextSpecific 6 Implicit pdu)
  , PdusSnmpTrap <$> option "snmpV2-trap" (tag ContextSpecific 7 Implicit pdu)
  , PdusReport <$> option "report" (tag ContextSpecific 8 Implicit pdu)
  ]

data PerHostV3 = PerHostV3
  { perHostV3ContextEngineId :: !ByteString
  , perHostV3AuthoritativeEngineId :: !ByteString
  , perHostV3ReceiverTime :: !Int32
  , perHostV3ReceiverBoots :: !Int32
  }

-- onlyMessageId :: AsnDecoding RequestId
-- onlyMessageId = sequence

messageV3 :: ByteString -> Crypto -> PerHostV3 -> AsnDecoding MessageV3
messageV3 fullBs crypto perHostV3 = sequence $ MessageV3
  <$  required "msgVersion" integer -- make this actually demand that it's 3
  <*> required "msgGlobalData" (headerData crypto)
  <*> required "msgSecurityParameters"
        (mapFailable (first ("while decoding security params" ++) . AsnDecoding.ber (usm fullBs crypto)) octetString)
  <*> required "msgData" (scopedPduDataDecoding crypto perHostV3)

headerData :: Crypto -> AsnDecoding HeaderData
headerData c = sequence $ HeaderData
  <$> required "msgID" (coerce int)
  <*> required "msgMaxSize" int32
  <*  required "msgFlags" (mapFailable (\w -> if E.cryptoFlags c == w
        then Right ()
        else Right ()
        -- Commented this out because sometimes you get back a report PDU.
        --
        -- else Left $ concat
        --   [ "wrong auth flags in header data: "
        --   , "expected " ++ printf "%08b" (E.cryptoFlags c)
        --   , " but found " ++ printf "%08b" w
        --   ]
      ) octetStringWord8)
  <*  required "msgSecurityModel" integer -- make sure this is actually 3

scopedPduDataDecoding :: Crypto -> PerHostV3 -> AsnDecoding ScopedPdu
scopedPduDataDecoding c perHostV3 = choice
  [ option "plaintext" scopedPdu
  , option "encryptedPDU" (mapFailable (\bs -> case c of
      AuthPriv (AuthParameters authType authPass) (PrivParameters privType privPass salt) -> do
        let privKey = passwordToKey authType privPass (perHostV3ContextEngineId perHostV3)
        case privType of
          PrivTypeAes -> error "write AES"
          PrivTypeDes -> do
            res <- desDecrypt privKey salt bs
            AsnDecoding.ber scopedPdu bs
      _ -> Left "not expecting an encrypted ScopedPdu"
    ) octetString)
  ]

scopedPdu :: AsnDecoding ScopedPdu
scopedPdu = sequence $ ScopedPdu
  <$> required "contextEngineID" octetString
  <*> required "contextName" octetString
  <*> required "data" pdus

usm :: ByteString -> Crypto -> AesSalt -> AsnDecoding Usm -- ((Crypto,Maybe MessageV3),Usm)
usm fullBs c = sequence $ Usm
  <$> required "msgAuthoritativeEngineID" octetString
  <*> required "msgAuthoritativeEngineBoots" int32
  <*> required "msgAuthoritativeEngineTime" int32
  <*> required "msgUserName" octetString
  <*  required "msgAuthenticationParameters" (mapFailable (\bs -> case cryptoAuth c of
      Nothing -> Right () -- should probably ensure that it's empty
      Just (AuthParameters _authType _authKey) ->
        -- should definitely validate the response. skipping this for now.
        Right ()
    ) octetString)
  <*  required "msgPrivacyParameters" (mapFailable (\bs -> case cryptoPriv c of
      Nothing -> Right ()
      Just (PrivParameters _ _) ->
        let bsSalt = LB.toStrict (Builder.toLazyByteString (Builder.word64BE salt))
         in if bsSalt == bs
              then Right ()
              else Left "salt does not match expected salt"
    ) octetString)


type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString

desDecrypt :: ByteString -> Salt -> Encrypted -> Either String Raw
desDecrypt privKey salt =
    stripBS . Priv.cbcDecrypt cipher iv
  where
    preIV = B.drop 8 (B.take 16 privKey)
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

stripBS :: ByteString -> Either String ByteString
stripBS bs =
    let bs' = B.drop 1 bs
        l1 = fromIntegral (B.head bs')
    in if testBit l1 7
        then case clearBit l1 7 of
                  0   -> Left "decoding snmp encountered error during decryption"
                  len ->
                    let size = uintbs (B.take len (B.drop 1 bs'))
                    in Right (B.take (size + len + 2) bs)
        else Right (B.take (l1 + 2) bs)
  where
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl' (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0


mkCipher :: (Priv.Cipher c) => ByteString -> c
mkCipher = (\(Priv.CryptoPassed x) -> x) . Priv.cipherInit
{-# INLINE mkCipher #-}

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

