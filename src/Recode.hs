{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}

{-# OPTIONS_GHC -Wall #-}

module Recode where

import Prelude hiding (sequence)
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
import qualified Data.Text.Encoding as TE
import qualified Text.PrettyPrint as PP
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Builder as Builder
import qualified Data.List as List
import qualified Data.Vector as Vector

data Enc a
  = EncSequence [Field a]
  | EncChoice (Choice a)
  | EncRetag TagAndExplicitness (Enc a)
  | EncUniversalValue (UniversalValue a)

data UniversalValue a
  = UniversalValueBoolean (a -> Bool) (Subtypes Bool)
  | UniversalValueInteger (a -> Integer) (Subtypes Integer)
  | UniversalValueOctetString (a -> ByteString) (Subtypes ByteString)
  | UniversalValueTextualString StringType (a -> Text) (Subtypes Text) (Subtypes Char)
  | UniversalValueObjectIdentifier (a -> ObjectIdentifier) (Subtypes ObjectIdentifier)

newtype Subtypes a = Subtypes { getSubtypes :: [Subtype a] }
  deriving (Monoid)

newtype ObjectIdentifier = ObjectIdentifier (Vector Integer)

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

instance Num TagAndExplicitness where
  (+) = error "TagAndExplicitness does not support addition"
  (-) = error "TagAndExplicitness does not support subtraction"
  (*) = error "TagAndExplicitness does not support multiplication"
  abs = error "TagAndExplicitness does not support abs"
  signum = error "TagAndExplicitness does not support signum"
  negate = error "TagAndExplicitness does not support negate"
  fromInteger n = TagAndExplicitness
    (Tag TagClassContextSpecific (fromIntegral n))
    Explicit

data IntegerBounds = IntegerBounds Integer Integer

data Choice a = Choice [a] (a -> ValueAndEncoding)
data ValueAndEncoding = forall b. ValueAndEncoding Int OptionName b (Enc b)
data Field a
  = forall b. FieldRequired FieldName (a -> b) (Enc b)
  | forall b. FieldOptional FieldName (a -> Maybe b) (Enc b)
  | forall b. FieldDefaulted FieldName (a -> b) b (b -> String) (b -> b -> Bool) (Enc b)

data TaggedByteString = TaggedByteString Construction Tag LB.ByteString
data Construction = Constructed | Primitive

newtype FieldName = FieldName { getFieldName :: String }
  deriving (IsString)
newtype OptionName = OptionName { getOptionName :: String }
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

tagClassPrefix :: TagClass -> String
tagClassPrefix x = case x of
  TagClassUniversal -> "UNIVERSAL "
  TagClassPrivate -> "PRIVATE "
  TagClassApplication -> "APPLICATION "
  TagClassContextSpecific -> ""

prettyPrintEnc :: Enc a -> String
prettyPrintEnc = PP.render . go where
  go :: forall b. Enc b -> PP.Doc
  go (EncUniversalValue u) = prettyPrintUniversalValue u
  go (EncRetag (TagAndExplicitness theTag expl) e) =
    PP.text (prettyPrintTag theTag ++ " " ++ ppExplicitness expl ++ " ") <> go e
  go (EncChoice (Choice allCtors getValAndEnc)) = (PP.$+$)
    "CHOICE"
    ( PP.nest 2 $ PP.vcat $ map (ppValEnc . getValAndEnc) allCtors)
  go (EncSequence fields) = (PP.$+$)
    "SEQUENCE"
    ( PP.nest 2 $ PP.vcat $ map ppField fields)
  ppField :: forall b. Field b -> PP.Doc
  ppField x = case x of
    FieldRequired (FieldName name) _ e -> PP.text (name ++ " ") <> go e
    FieldOptional (FieldName name) _ e -> PP.text (name ++ " OPTIONAL ") <> go e
    FieldDefaulted (FieldName name) _ defVal showVal _ e ->
      PP.text (name ++ " DEFAULT " ++ showVal defVal ++ " ") <> go e
  ppValEnc :: ValueAndEncoding -> PP.Doc
  ppValEnc (ValueAndEncoding _ (OptionName name) _ enc) = PP.text (name ++ " ") <> go enc
  ppExplicitness :: Explicitness -> String
  ppExplicitness x = case x of
    Implicit -> "IMPLICIT"
    Explicit -> "EXPLICIT"


prettyPrintTag :: Tag -> String
prettyPrintTag (Tag c n) = "[" ++ tagClassPrefix c ++ show n ++ "]"

prettyPrintUniversalValue :: UniversalValue x -> PP.Doc
prettyPrintUniversalValue x = case x of
  UniversalValueBoolean _ _ -> PP.text "BOOLEAN"
  UniversalValueInteger _ ss -> PP.text $ "INTEGER" ++ strSubtypes show ss
  UniversalValueOctetString _ _ -> PP.text "OCTET STRING"
  UniversalValueObjectIdentifier _ _ -> PP.text "OBJECT IDENTIFIER"
  UniversalValueTextualString typ _ _ _ -> PP.text (strStringType typ)

strStringType :: StringType -> String
strStringType x = case x of
  Utf8String -> "UTF8String"
  NumericString -> "NumericString"
  PrintableString -> "PrintableString"
  TeletexString -> "TeletexString"
  VideotexString -> "VideotexString"
  IA5String -> "IA5String"
  GraphicString -> "GraphicString"
  VisibleString -> "VisibleString"
  GeneralString -> "GeneralString"
  UniversalString -> "UniversalString"
  CharacterString -> "CHARACTER STRING"
  BmpString -> "BMPString"

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

strSubtypes :: (a -> String) -> Subtypes a -> String
strSubtypes f (Subtypes ss)
  | length ss == 0 = ""
  | otherwise = " (" ++ List.intercalate " | " (map (strSubtype f) ss) ++ ")"

strSubtype :: (a -> String) -> Subtype a -> String
strSubtype f x = case x of
  SubtypeSingleValue a -> f a
  SubtypeValueRange lo hi -> f lo ++ " .. " ++ f hi

makeTag :: TagClass -> Int -> Tag
makeTag = Tag

sequence :: [Field a] -> Enc a
sequence = EncSequence

choice :: [a] -> (a -> ValueAndEncoding) -> Enc a
choice xs f = EncChoice (Choice xs f)

option :: Int -> OptionName -> b -> Enc b -> ValueAndEncoding
option = ValueAndEncoding

tag :: TagAndExplicitness -> Enc a -> Enc a
tag = EncRetag

required :: FieldName -> (a -> b) -> Enc b -> Field a
required = FieldRequired

optional :: FieldName -> (a -> Maybe b) -> Enc b -> Field a
optional = FieldOptional

defaulted :: (Eq b, Show b) => FieldName -> (a -> b) -> Enc b -> b -> Field a
defaulted name getVal enc defVal = FieldDefaulted name getVal defVal show (==) enc

objectIdentifier :: Enc ObjectIdentifier
objectIdentifier = EncUniversalValue (UniversalValueObjectIdentifier id mempty)

integer :: Enc Integer
integer = EncUniversalValue (UniversalValueInteger id mempty)

integerRanged :: Integer -> Integer -> Enc Integer
integerRanged lo hi = EncUniversalValue
  (UniversalValueInteger id (Subtypes [SubtypeValueRange lo hi]))

octetString :: Enc ByteString
octetString = EncUniversalValue (UniversalValueOctetString id mempty)

utf8String :: Enc Text
utf8String = EncUniversalValue (UniversalValueTextualString Utf8String id mempty mempty)

person :: Enc Person
person = sequence
  [ required "name" personName octetString
  , required "age" personAge integer
  ]

universalValueTag :: UniversalValue a -> Int
universalValueTag x = case x of
  UniversalValueOctetString _ _ -> 4
  UniversalValueBoolean _ _ -> 1
  UniversalValueInteger _ _ -> 2
  UniversalValueObjectIdentifier _ _ -> 6
  UniversalValueTextualString typ _ _ _ -> tagNumStringType typ

univsersalValueConstruction :: UniversalValue a -> Construction
univsersalValueConstruction x = case x of
  UniversalValueOctetString _ _ -> Constructed
  UniversalValueBoolean _ _ -> Primitive
  UniversalValueInteger _ _ -> Primitive
  UniversalValueTextualString _ _ _ _ -> Primitive
  UniversalValueObjectIdentifier _ _ -> Primitive

encodeBer :: Enc a -> a -> LB.ByteString
encodeBer e = encodeTaggedByteString . encodeBerInternal e

-- | The ByteString that accompanies the tag does not
--   include its own length.
encodeBerInternal :: Enc a -> a -> TaggedByteString
encodeBerInternal x a = case x of
  EncRetag (TagAndExplicitness outerTag explicitness) e ->
    let TaggedByteString construction innerTag lbs = encodeBerInternal e a
     in case explicitness of
          Implicit -> TaggedByteString construction outerTag lbs
          Explicit -> TaggedByteString Constructed outerTag (encodeTaggedByteString (TaggedByteString construction innerTag lbs))
  EncUniversalValue p -> TaggedByteString (univsersalValueConstruction p) (makeTag TagClassUniversal (universalValueTag p)) (encodePrimitiveBer p a)
  EncChoice (Choice _ f) -> case f a of
    ValueAndEncoding _ _ b enc2 -> encodeBerInternal enc2 b
  EncSequence fields -> TaggedByteString Constructed sequenceTag (foldMap (encodeField a) fields)

sequenceTag :: Tag
sequenceTag = Tag TagClassUniversal 16

-- Factor out some of the encoding stuff here into another function
encodeField :: a -> Field a -> LB.ByteString
encodeField a x = case x of
  FieldRequired _ func enc -> encodeTaggedByteString (encodeBerInternal enc (func a))
  FieldDefaulted _ func defVal _ eqVal enc ->
    let val = func a
     in if eqVal defVal val
          then mempty
          else encodeTaggedByteString (encodeBerInternal enc val)
  FieldOptional _ mfunc enc -> case mfunc a of
    Nothing -> mempty
    Just v -> encodeTaggedByteString (encodeBerInternal enc v)

encodeTaggedByteString :: TaggedByteString -> LB.ByteString
encodeTaggedByteString (TaggedByteString construction theTag lbs) =
  encodeTag construction theTag <> encodeLength (LB.length lbs) <> lbs

encodeTag :: Construction -> Tag -> LB.ByteString
encodeTag c (Tag tclass tnum)
  | tnum < 31 = LB.singleton (firstThreeBits .|. intToWord8 tnum)
  | otherwise = error "tag number above 30: write this"
  where
  !firstThreeBits = constructionBit c .|. tagClassBit tclass

encodeLength :: Int64 -> LB.ByteString
encodeLength x
  | x < 128 = LB.singleton (int64ToWord8 x)
  | otherwise = error "length greater than 127: write this"

int64ToWord8 :: Int64 -> Word8
int64ToWord8 = fromIntegral
{-# INLINE int64ToWord8 #-}

intToWord8 :: Int -> Word8
intToWord8 = fromIntegral
{-# INLINE intToWord8 #-}

-- Bit six is 1 when a value is constructed.
constructionBit :: Construction -> Word8
constructionBit x = case x of
  Constructed -> 32
  Primitive -> 0

-- Controls upper two bits in the octet
tagClassBit :: TagClass -> Word8
tagClassBit x = case x of
  TagClassUniversal -> 0
  TagClassApplication -> 64
  TagClassContextSpecific -> 128
  TagClassPrivate -> 192

encodePrimitiveBer :: UniversalValue a -> a -> LB.ByteString
encodePrimitiveBer p x = case p of
  UniversalValueTextualString typ f _ _ -> LB.fromStrict (encodeText typ (f x))
  UniversalValueOctetString f _ -> LB.fromStrict (f x)
  UniversalValueObjectIdentifier f _ -> oidBE (f x)
  UniversalValueBoolean f _ -> case f x of
    True -> LB.singleton 1
    False -> LB.singleton 0
  UniversalValueInteger f _ -> integerBE (f x)

encodeText :: StringType -> Text -> ByteString
encodeText x t = case x of
  Utf8String -> TE.encodeUtf8 t
  _ -> error "encodeText: handle more ASN.1 string types"

data Person = Person
  { personName :: ByteString
  , personAge :: Integer
  , personConcern :: Concern
  }

data Concern
  = ConcernNumber Integer
  | ConcernSpeech String

-- data Human = Human
--   { humanName :: Text
--   , humanFirstWords :: Text
--   , humanAge :: Maybe Age
--   }
--
-- data Age = AgeBiblical Integer | AgeModern Integer
--
-- human :: Enc Human
-- human = sequence
--   [ required "name" humanName utf8String
--   , defaulted "first-words" humanFirstWords utf8String "Hello World"
--   , optional "age" humanAge age
--   ]
--
-- exampleHuman :: Human
-- exampleHuman = Human "Adam" "Hello World" (Just $ AgeBiblical 900)
--
-- age :: Enc Age
-- age = choice [AgeBiblical 0, AgeModern 0] $ \x -> case x of
--   AgeBiblical n -> option 0 "biblical" n $ tag 0 $ integerRanged 0 1000
--   AgeModern n -> option 1 "modern" n $ tag 1 $ integerRanged 0 100

integerBE :: Integer -> LB.ByteString
integerBE i
  | i < 128 && i > (-129) = Builder.toLazyByteString (Builder.int8 (fromIntegral i))
  | otherwise = if i > 0
      then let lb = Builder.toLazyByteString (goPos i)
            in if LB.head lb > 127 then LB.cons 0 lb else lb
      else error "integerBE: handle the negative case"
  where
  goPos :: Integer -> Builder
  goPos n1 = if n1 == 0
    then mempty
    else let (!n2,!byteVal) = quotRem n1 256
          in goPos n2 <> Builder.word8 (fromIntegral byteVal)

oidBE :: ObjectIdentifier -> LB.ByteString
oidBE (ObjectIdentifier nums1)
  | Vector.length nums1 > 2 =
      let !n1 = Vector.unsafeIndex nums1 0
          !n2 = Vector.unsafeIndex nums1 1
          !nums2 = Vector.unsafeDrop 2 nums1
          !firstOctet = fromIntegral n1 * 40 + fromIntegral n2 :: Word8
       in Builder.toLazyByteString (Builder.word8 firstOctet <> foldMap multiByteBase127Encoding nums2)
  | otherwise = error "oidBE: OID with less than 3 identifiers"

multiByteBase127Encoding :: Integer -> Builder
multiByteBase127Encoding i0 =
  let (!i1,!byteVal) = quotRem i0 127
   in go i1 <> Builder.word8 (fromIntegral byteVal)
  where
  go n1 = if n1 == 0
    then mempty
    else let (!n2,!byteVal) = quotRem n1 128
          in go n2 <> Builder.word8 (1 .|. fromIntegral byteVal)

integerLog2 :: Integer -> Int
integerLog2 i = I# (integerLog2# i)

