{-# LANGUAGE OverloadedStrings #-}

module Net.Snmp.Encoding where

import Prelude hiding (sequence)
import Recode
import Net.Snmp.Types
import Data.Coerce (coerce)
import qualified Data.ByteString as ByteString
import qualified Data.Vector as Vector

messageV2 :: AsnEncoding MessageV2
messageV2 = error "write me"

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
    $ implicitTag (Tag TagClassApplication 0) octetStringWord32
  ApplicationSyntaxCounter n -> option 1 "counter-value" n
    $ implicitTag (Tag TagClassApplication 1) word32
  ApplicationSyntaxTimeTicks n -> option 2 "timeticks-value" n
    $ implicitTag (Tag TagClassApplication 3) word32
  ApplicationSyntaxArbitrary n -> option 3 "arbitrary-value" n
    $ implicitTag (Tag TagClassApplication 4) octetString
  ApplicationSyntaxBigCounter n -> option 4 "big-counter-value" n
    $ implicitTag (Tag TagClassApplication 6) word64
  ApplicationSyntaxUnsignedInteger n -> option 5 "unsigned-integer-value" n
    $ implicitTag (Tag TagClassApplication 2) word32

pdu :: AsnEncoding Pdu
pdu = sequence
  [ required "request-id" pduRequestId (coerce int32)
  , required "error-status" pduErrorStatus (coerce integer)
  , required "error-index" pduErrorIndex (coerce int32)
  , required "variable-bindings" pduVariableBindings (sequenceOf varBind)
  ]
  
defaultObjectIdentifier :: ObjectIdentifier
defaultObjectIdentifier = ObjectIdentifier (Vector.fromList [1,3,6])

