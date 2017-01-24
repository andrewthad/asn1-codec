{-# LANGUAGE OverloadedStrings #-}

module Net.Snmp.Decoding where

import Prelude hiding (sequence,null)
import Language.Asn.Decoding
import Language.Asn.Types
import Net.Snmp.Types
import Data.Coerce (coerce)
import Data.ByteString (ByteString)
import Text.Printf (printf)
import Data.Bifunctor
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

-- onlyMessageId :: AsnDecoding RequestId
-- onlyMessageId = sequence

messageV3 :: ByteString -> Crypto -> AsnDecoding MessageV3
messageV3 fullBs crypto = sequence $ MessageV3
  <$  required "msgVersion" integer -- make this actually demand that it's 3
  <*> required "msgGlobalData" (headerData crypto)
  <*> required "msgSecurityParameters" 
        (mapFailable (first ("while decoding security params" ++) . AsnDecoding.ber (usm fullBs crypto)) octetString)
  <*> required "msgData" (scopedPduDataDecoding crypto)

headerData :: Crypto -> AsnDecoding HeaderData
headerData c = sequence $ HeaderData
  <$> required "msgID" (coerce int)
  <*> required "msgMaxSize" int32
  <*  required "msgFlags" (mapFailable (\w -> if E.cryptoFlags c == w
        then Right ()
        else Right ()
        -- else Left $ concat
        --   [ "wrong auth flags in header data: "
        --   , "expected " ++ printf "%08b" (E.cryptoFlags c)
        --   , " but found " ++ printf "%08b" w
        --   ]
      ) octetStringWord8)
  <*  required "msgSecurityModel" integer -- make sure this in actually 3

scopedPduDataDecoding :: Crypto -> AsnDecoding ScopedPdu
scopedPduDataDecoding c = choice
  [ option "plaintext" scopedPdu
  , option "encryptedPDU" (mapFailable (\_ -> Left "write scopedPduDataDecoding crypto") null)
  ]

scopedPdu :: AsnDecoding ScopedPdu
scopedPdu = sequence $ ScopedPdu 
  <$> required "contextEngineID" octetString
  <*> required "contextName" octetString
  <*> required "data" pdus

usm :: ByteString -> Crypto -> AsnDecoding Usm -- ((Crypto,Maybe MessageV3),Usm)
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
      Just (PrivParameters _ _ salt) -> 
        let bsSalt = LB.toStrict (Builder.toLazyByteString (Builder.word64BE salt))
         in if bsSalt == bs
              then Right ()
              else Left "salt does not match expected salt"
    ) octetString)


