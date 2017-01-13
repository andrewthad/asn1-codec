{-# LANGUAGE BangPatterns #-}

module Net.Snmp.Types where

import Language.Asn.Types
import Data.Int
import Data.Word
import Data.ByteString (ByteString)
import Data.Vector (Vector)

newtype RequestId = RequestId { getRequestId :: Int }
  deriving (Eq,Ord,Show,Read)
newtype ErrorIndex = ErrorIndex { getErrorIndex :: Int32 }
  deriving (Eq,Show)
newtype ErrorStatus = ErrorStatus { getErrorStatus :: Integer }
  deriving (Eq,Show)

data ObjectSyntax
  = ObjectSyntaxSimple !SimpleSyntax
  | ObjectSyntaxApplication !ApplicationSyntax
  deriving (Eq,Show)

data SimpleSyntax
  = SimpleSyntaxInteger !Int32
  | SimpleSyntaxString !ByteString
  | SimpleSyntaxObjectId !ObjectIdentifier
  deriving (Eq,Show)

data ApplicationSyntax
  = ApplicationSyntaxIpAddress !Word32
  | ApplicationSyntaxCounter !Word32
  | ApplicationSyntaxTimeTicks !Word32
  | ApplicationSyntaxArbitrary !ByteString
  | ApplicationSyntaxBigCounter !Word64
  | ApplicationSyntaxUnsignedInteger !Word32
  deriving (Eq,Show)

data VarBind = VarBind
  { varBindName :: !ObjectIdentifier
  , varBindResult :: !BindingResult
  } deriving (Eq,Show)

data BindingResult
  = BindingResultValue !ObjectSyntax
  | BindingResultUnspecified
  | BindingResultNoSuchObject
  | BindingResultNoSuchInstance
  | BindingResultEndOfMibView
  deriving (Eq,Show)

data Pdus
  = PdusGetRequest !Pdu
  | PdusGetNextRequest !Pdu
  | PdusGetBulkRequest !BulkPdu
  | PdusResponse !Pdu
  | PdusSetRequest !Pdu
  | PdusInformRequest !Pdu
  | PdusSnmpTrap !Pdu
  | PdusReport !Pdu
  deriving (Eq,Show)

-- | A message as defined by RFC1157. The @version@ field is omitted
--   since it is required to be 1. The encoding and decoding of 'Message'
--   do have this field present though.
data MessageV2 = MessageV2
  { messageV2CommunityString :: !ByteString
  , messageV2Data :: !Pdus
    -- ^ In the ASN.1 definition of @Message@, this field is an @ANY@.
    --   In practice, it is always @PDUs@.
  } deriving (Eq,Show)

-- data MessageV3 = MessageV3
--   { messageV3Version :: !Int
--   , messageV3GlobalData :: !HeaderData
--   , messageV3SecurityParameters :: !ByteString
--   , messageV3Data :: !ScopedPduData
--   }
--
-- data HeaderData = HeaderData
--   { headerDataId :: !MessageId
--   , headerDataMaxSize :: !Int
--   , headerDataFlags :: !Word8
--   , headerDataSecurityModel :: !Int
--   }

data Pdu = Pdu
  { pduRequestId :: !RequestId
  , pduErrorStatus :: !ErrorStatus
  , pduErrorIndex :: !ErrorIndex
  , pduVariableBindings :: !(Vector VarBind)
  } deriving (Eq,Show)

data BulkPdu = BulkPdu
  { bulkPduRequestId :: !RequestId
  , bulkPduNonRepeaters :: !Int32
  , bulkPduMaxRepetitions :: !Int32
  , bulkPduVariableBindings :: !(Vector VarBind)
  } deriving (Eq,Show)



