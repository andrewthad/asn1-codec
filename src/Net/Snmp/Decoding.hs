{-# LANGUAGE OverloadedStrings #-}

module Net.Snmp.Decoding where

import Prelude hiding (sequence,null)
import Language.Asn.Decoding
import Language.Asn.Types
import Net.Snmp.Types
import Data.Coerce (coerce)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

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
  ]


