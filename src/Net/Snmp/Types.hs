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

data MessageV3 = MessageV3
  { messageV3GlobalData :: !HeaderData
  , messageV3SecurityParameters :: !Usm
  , messageV3Data :: !ScopedPdu
  } deriving (Eq,Show)

data HeaderData = HeaderData
  { headerDataId :: !RequestId
  , headerDataMaxSize :: !Int32
  , headerDataFlags :: !Word8
  -- The Security Model is omitted because we only
  -- support USM (User Security Model, represented by the number 3),
  -- which seems to be the only one actually in use.
  -- , headerDataSecurityModel :: !Int
  } deriving (Eq,Show)

data AuthFlags = AuthFlagsNoAuthNoPriv | AuthFlagsAuthNoPriv | AuthFlagsAuthPriv

data AuthType = AuthTypeMd5 | AuthTypeSha
  deriving (Eq,Show)
data PrivType = PrivTypeDes | PrivTypeAes
  deriving (Eq,Show)

data Crypto
  = NoAuthNoPriv
  | AuthNoPriv !AuthParameters
  | AuthPriv !AuthParameters !PrivParameters

data AuthParameters = AuthParameters
  { authParametersType :: !AuthType
  , authParametersKey :: !ByteString
  } deriving (Eq,Show)

data PrivParameters = PrivParameters
  { privParametersType :: !PrivType
  , privParametersKey :: !ByteString
  } deriving (Eq,Show)

newtype AesSalt = AesSalt { getAesSalt :: Word64 }

cryptoFlags :: Crypto -> Word8
cryptoFlags x = case x of
  NoAuthNoPriv -> 0
  AuthNoPriv _ -> 1
  AuthPriv _ _ -> 3

cryptoAuth :: Crypto -> Maybe AuthParameters
cryptoAuth x = case x of
  NoAuthNoPriv -> Nothing
  AuthNoPriv a -> Just a
  AuthPriv a _ -> Just a

cryptoPriv :: Crypto -> Maybe PrivParameters
cryptoPriv x = case x of
  NoAuthNoPriv -> Nothing
  AuthNoPriv _ -> Nothing
  AuthPriv _ a -> Just a

data Parametered a = Parametered
  { parameteredValue :: !a
  , parameteredParameter :: !ByteString
  } deriving (Eq,Show)

data ScopedPduData
  = ScopedPduDataPlaintext !ScopedPdu
  | ScopedPduDataEncrypted !ByteString

data ScopedPdu = ScopedPdu
  { scopedPduContextEngineId :: !ByteString
  , scopedPduContextName :: !ByteString
  , scopedPduData :: !Pdus
  } deriving (Eq,Show)

data Usm = Usm
  { usmEngineId :: !ByteString
  , usmEngineBoots :: !Int32
  , usmEngineTime :: !Int32
  , usmUserName :: !ByteString
  , usmAuthenticationParameters :: !ByteString
  , usmPrivacyParameters :: !ByteString
  } deriving (Eq,Show)

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



