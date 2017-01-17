{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RankNTypes #-}

{-# OPTIONS_GHC -Wall #-}

module Language.Asn.Types.Internal where

import Prelude hiding (sequence,null)
import Data.String
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import Data.Text (Text)
import Data.Monoid
import Data.Word
import Data.Int
import Data.Bits
import Data.Vector (Vector)
import GHC.Int (Int(..))
import GHC.Integer.Logarithms (integerLog2#)
import Data.Foldable
import Data.Hashable (Hashable(..))
import qualified Data.Text.Encoding as TE
import qualified Text.PrettyPrint as PP
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Builder as Builder
import qualified Data.List as List
import qualified Data.Vector as Vector

data AsnEncoding a
  = EncSequence [Field a]
  | forall b. EncSequenceOf (a -> [b]) (AsnEncoding b)
  | EncChoice (Choice a)
  | EncRetag TagAndExplicitness (AsnEncoding a)
  | EncUniversalValue (UniversalValue a)

data UniversalValue a
  = UniversalValueBoolean (a -> Bool) (Subtypes Bool)
  | UniversalValueInteger (a -> Integer) (Subtypes Integer)
  | UniversalValueNull
  | UniversalValueOctetString (a -> ByteString) (Subtypes ByteString)
  | UniversalValueTextualString StringType (a -> Text) (Subtypes Text) (Subtypes Char)
  | UniversalValueObjectIdentifier (a -> ObjectIdentifier) (Subtypes ObjectIdentifier)

newtype Subtypes a = Subtypes { getSubtypes :: [Subtype a] }
  deriving (Monoid)

newtype ObjectIdentifier = ObjectIdentifier (Vector Integer)
  deriving (Eq,Ord,Show,Read)

instance Hashable ObjectIdentifier where
  hash (ObjectIdentifier v) = hash (Vector.toList v)
  hashWithSalt s (ObjectIdentifier v) = hashWithSalt s (Vector.toList v)

data Subtype a
  = SubtypeSingleValue a -- This also acts as PermittedAlphabet
  | SubtypeValueRange a a

data StringType
  = Utf8String
  | NumericString
  | PrintableString
  | TeletexString
  | VideotexString
  | IA5String
  | GraphicString
  | VisibleString
  | GeneralString
  | UniversalString
  | CharacterString
  | BmpString

data Explicitness = Explicit | Implicit
data TagAndExplicitness = TagAndExplicitness Tag Explicitness

data Choice a = Choice [a] (a -> ValueAndEncoding)
data ValueAndEncoding = forall b. ValueAndEncoding Int OptionName b (AsnEncoding b)
data Field a
  = forall b. FieldRequired FieldName (a -> b) (AsnEncoding b)
  | forall b. FieldOptional FieldName (a -> Maybe b) (AsnEncoding b)
  | forall b. FieldDefaulted FieldName (a -> b) b (b -> String) (b -> b -> Bool) (AsnEncoding b)

data TaggedByteString = TaggedByteString !Construction !Tag !LB.ByteString
data TaggedStrictByteString = TaggedStrictByteString !Construction !Tag !ByteString
data Construction = Constructed | Primitive
  deriving (Show,Eq)

newtype FieldName = FieldName { getFieldName :: String }
  deriving (IsString)
newtype OptionName = OptionName { getOptionName :: String }
  deriving (IsString)

data TagClass
  = Universal
  | Application
  | Private
  | ContextSpecific
  deriving (Show,Eq)

data Tag = Tag
  { tagClass :: TagClass
  , tagNumber :: Int
  } deriving (Show,Eq)

instance Num TagAndExplicitness where
  (+) = error "TagAndExplicitness does not support addition"
  (-) = error "TagAndExplicitness does not support subtraction"
  (*) = error "TagAndExplicitness does not support multiplication"
  abs = error "TagAndExplicitness does not support abs"
  signum = error "TagAndExplicitness does not support signum"
  negate = error "TagAndExplicitness does not support negate"
  fromInteger n = TagAndExplicitness
    (Tag ContextSpecific (fromIntegral n))
    Explicit

instance Num Tag where
  (+) = error "Tag does not support addition"
  (-) = error "Tag does not support subtraction"
  (*) = error "Tag does not support multiplication"
  abs = error "Tag does not support abs"
  signum = error "Tag does not support signum"
  negate = error "Tag does not support negate"
  fromInteger n = Tag ContextSpecific (fromIntegral n)


------------------------------
-- Stuff specific to decoding
------------------------------

data AsnDecoding a
  = AsnDecodingUniversal (UniverseDecoding a)
  | forall b. AsnDecodingSequenceOf ([b] -> a) (AsnDecoding b)
  | forall b. AsnDecodingConversion (AsnDecoding b) (b -> Either String a)
  | AsnDecodingRetag TagAndExplicitness (AsnDecoding a)
  | AsnDecodingSequence (FieldDecoding a)
  | AsnDecodingChoice [OptionDecoding a]

deriving instance Functor AsnDecoding

data Ap f a where
  Pure :: a -> Ap f a
  Ap :: f a -> Ap f (a -> b) -> Ap f b

instance Functor (Ap f) where
  fmap f (Pure a)   = Pure (f a)
  fmap f (Ap x y)   = Ap x ((f .) <$> y)

instance Applicative (Ap f) where
  pure = Pure
  Pure f <*> y = fmap f y
  Ap x y <*> z = Ap x (flip <$> y <*> z)

data OptionDecoding a = OptionDecoding OptionName (AsnDecoding a)
  deriving (Functor)

newtype FieldDecoding a = FieldDecoding (Ap FieldDecodingPart a)
  deriving (Functor,Applicative)

data FieldDecodingPart a
  = FieldDecodingRequired FieldName (AsnDecoding a)
  | FieldDecodingDefault FieldName (AsnDecoding a) a (a -> String)
  | forall b. FieldDecodingOptional FieldName (AsnDecoding b) (Maybe b -> a)

data UniverseDecoding a
  = UniverseDecodingInteger (Integer -> a) (Subtypes Integer)
  | UniverseDecodingTextualString StringType (Text -> a) (Subtypes Text) (Subtypes Char)
  | UniverseDecodingOctetString (ByteString -> a) (Subtypes ByteString)
  | UniverseDecodingObjectIdentifier (ObjectIdentifier -> a) (Subtypes ObjectIdentifier)
  | UniverseDecodingNull a
  deriving (Functor)

newtype DecodePart a = DecodePart { getDecodePart :: ByteString -> Either String (a,ByteString) }
  deriving (Functor)

instance Applicative DecodePart where
  pure a = DecodePart (\bs -> Right (a,bs))
  DecodePart f <*> DecodePart g = DecodePart $ \bs1 -> do
    (h,bs2) <- f bs1
    (a,bs3) <- g bs2
    return (h a, bs3)

runAp :: Applicative g => (forall x. f x -> g x) -> Ap f a -> g a
runAp _ (Pure x) = pure x
runAp u (Ap f x) = flip id <$> u f <*> runAp u x

liftAp :: f a -> Ap f a
liftAp x = Ap x (Pure id)
{-# INLINE liftAp #-}

--------------------------
-- Functions common to encoding and decoding
--------------------------

-- Bit six is 1 when a value is constructed.
constructionBit :: Construction -> Word8
constructionBit x = case x of
  Constructed -> 32
  Primitive -> 0

-- Controls upper two bits in the octet
tagClassBit :: TagClass -> Word8
tagClassBit x = case x of
  Universal -> 0
  Application -> 64
  ContextSpecific -> 128
  Private -> 192

sequenceTag :: Tag
sequenceTag = Tag Universal 16

tagNumStringType :: StringType -> Int
tagNumStringType x = case x of
  Utf8String -> 12
  NumericString -> 18
  PrintableString -> 19
  TeletexString -> 20
  VideotexString -> 21
  IA5String -> 22
  GraphicString -> 25
  VisibleString -> 26
  GeneralString -> 27
  UniversalString -> 28
  CharacterString -> 29
  BmpString -> 30
