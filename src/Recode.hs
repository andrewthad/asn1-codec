{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Recode where

import Prelude hiding (sequence)
import Data.String
import Data.ByteString (ByteString)
import qualified Text.PrettyPrint as PP
import qualified Data.ByteString.Lazy as LB

data Enc a
  = EncSequence [Field a]
  | EncChoice (Choice a)
  | EncRetag Retag (Enc a)
  | EncUniversalValue (UniversalValue a)

data UniversalValue a where
  UniversalValueBoolean :: UniversalValue Bool
  UniversalValueInteger :: Maybe IntegerBounds -> UniversalValue Integer
  UniversalValueOctetString :: UniversalValue ByteString

data Primitive a where
  PrimitiveInteger :: Maybe IntegerBounds -> Primitive Integer
  PrimitiveBool :: Primitive Bool
  PrimitiveString :: Primitive String

data Retag = Explicit Tag | Implicit Tag | Tagless
data IntegerBounds = IntegerBounds Integer Integer

data Choice a = Choice [a] (a -> ValueAndEncoding)
data ValueAndEncoding = forall b. ValueAndEncoding b (Enc b)
data Field a
  = forall b. FieldRequired FieldName (a -> b) (Enc b)
  | forall b. FieldOptional FieldName (a -> Maybe b) (Enc b)
data TaggedByteString = TaggedByteString Tag LB.ByteString

newtype FieldName = FieldName String
  deriving (IsString)

data TagClass
  = TagClassUniversal
  | TagClassApplication
  | TagClassPrivate
  | TagClassContextSpecific

data Tag = Tag
  { tagClass :: TagClass
  , tagNumber :: Int
  }

makeTag :: TagClass -> Int -> Tag
makeTag = Tag

sequence :: [Field a] -> Enc a
sequence = EncSequence

required :: FieldName -> (a -> b) -> Enc b -> Field a
required = FieldRequired

integer :: Enc Integer
integer = EncUniversalValue (UniversalValueInteger Nothing)

byteString :: Enc ByteString
byteString = EncUniversalValue UniversalValueOctetString

person :: Enc Person
person = sequence
  [ required "name" personName byteString
  , required "age" personAge integer
  ]

universalValueTag :: UniversalValue a -> Int
universalValueTag x = case x of
  UniversalValueOctetString -> 4
  UniversalValueBoolean -> 1
  UniversalValueInteger _ -> 2

-- | The ByteString that accompanies the tag does not
--   include its own length.
encodeBer :: Enc a -> a -> TaggedByteString
encodeBer x a = case x of
  EncTag outerRetag e ->
    let TaggedByteString innerTag lbs = encodeBer e
     in case outerRetag of
          Tagless -> TaggedByteString innerTag lbs
          Implicit outerTag -> TaggedByteString outerTag lbs
          Explicit outerTag -> TaggedByteString outerTag ( <> lbs)
  EncUniversalValue p -> TaggedByteString (makeTag TagClassUniversal (universalValueTag p)) (encodePrimitiveBer p a)

encodePrimitiveBer :: UniversalValue a -> a -> LB.ByteString
encodePrimitiveBer p x = case p of
  UniversalValueOctetString -> LB.fromStrict x
  UniversalValueBoolean -> case x of
    True -> LB.singleton 1
    False -> LB.singleton 0
  UniversalValueInteger _ -> error "write integer encoding"

data Person = Person
  { personName :: ByteString
  , personAge :: Integer
  , personConcern :: Concern
  }

data Concern
  = ConcernNumber Integer
  | ConcernSpeech String

