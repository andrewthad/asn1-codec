{-# LANGUAGE BangPatterns #-}

module Net.Snmp.Types where

import Recode
import Data.Int
import Data.Word
import Data.ByteString (ByteString)
import Data.Vector (Vector)

newtype RequestId = RequestId { getRequestId :: Int32 }
newtype ErrorIndex = ErrorIndex { getErrorIndex :: Int32 }
newtype ErrorStatus = ErrorStatus { getErrorStatus :: Integer }

data ObjectSyntax
  = ObjectSyntaxSimple SimpleSyntax
  | ObjectSyntaxApplication ApplicationSyntax

data SimpleSyntax
  = SimpleSyntaxInteger Int32
  | SimpleSyntaxString ByteString
  | SimpleSyntaxObjectId ObjectIdentifier

data ApplicationSyntax
  = ApplicationSyntaxIpAddress Word32
  | ApplicationSyntaxCounter Word32
  | ApplicationSyntaxTimeTicks Word32
  | ApplicationSyntaxArbitrary ByteString
  | ApplicationSyntaxBigCounter Word64
  | ApplicationSyntaxUnsignedInteger Word32

data VarBind = VarBind
  { varBindName :: !ObjectIdentifier
  , varBindResult :: !BindingResult
  }

data BindingResult 
  = BindingResultValue ObjectSyntax
  | BindingResultUnspecified
  | BindingResultNoSuchObject
  | BindingResultNoSuchInstance
  | BindingResultEndOfMibView

data Pdus
  = PdusGetRequest Pdu
  | PdusGetNextRequest Pdu
  | PdusGetBulkRequest BulkPdu
  | PdusResponse Pdu
  | PdusSetRequest Pdu
  | PdusInformRequest Pdu
  | PdusSnmpTrap Pdu
  | PdusReportPdu Pdu

data MessageV2 = Message
  { messageV2Version :: !Int
  , messageV2CommunityString :: !ByteString
  , messageV2Pdu :: !Pdus
  }

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
  }

data BulkPdu = BulkPdu
  { bulkPduRequestId :: !RequestId
  , bulkPduNonRepeaters :: !Int32
  , bulkPduMaxRepetitions :: !Int32
  , bulkPduVariableBindings :: !(Vector VarBind)
  }



