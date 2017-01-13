{-# LANGUAGE OverloadedStrings #-}

module Net.Snmp.Encoding where

import Prelude hiding (sequence,null)
import Language.Asn.Encoding
import Language.Asn.Types
import Net.Snmp.Types
import Data.Coerce (coerce)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

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
  [ required "request-id" pduRequestId (coerce int32)
  , required "error-status" pduErrorStatus (coerce integer)
  , required "error-index" pduErrorIndex (coerce int32)
  , required "variable-bindings" pduVariableBindings (sequenceOf varBind)
  ]

bulkPdu :: AsnEncoding BulkPdu
bulkPdu = sequence
  [ required "request-id" bulkPduRequestId (coerce int32)
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


