{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}

module Recode where

import Prelude hiding (sequence)
import Data.String
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Monoid
import Data.Word
import Data.Int
import Data.Bits
import Data.Vector (Vector)
import GHC.Int (Int(..))
import GHC.Integer.Logarithms (integerLog2#)
import qualified Text.PrettyPrint as PP
import qualified Data.ByteString.Lazy as LB
import qualified Data.List as List

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

newtype Subtypes a = Subtypes { getSubtypes :: [Subtype a] }
  deriving (Monoid)

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

univsersalValueConstruction :: UniversalValue a -> Construction
univsersalValueConstruction x = case x of
  UniversalValueOctetString _ _ -> Constructed
  UniversalValueBoolean _ _ -> Primitive
  UniversalValueInteger _ _ -> Primitive

-- | The ByteString that accompanies the tag does not
--   include its own length.
encodeBer :: Enc a -> a -> TaggedByteString
encodeBer x a = case x of
  EncRetag (TagAndExplicitness outerTag explicitness) e ->
    let TaggedByteString construction innerTag lbs = encodeBer e a
     in case explicitness of
          Implicit -> TaggedByteString construction outerTag lbs
          Explicit -> TaggedByteString Constructed outerTag 
            (encodeTag construction innerTag <> encodeLength (LB.length lbs) <> lbs)
  EncUniversalValue p -> TaggedByteString (univsersalValueConstruction p) (makeTag TagClassUniversal (universalValueTag p)) (encodePrimitiveBer p a)

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
  UniversalValueOctetString f _ -> LB.fromStrict (f x)
  UniversalValueBoolean f _ -> case f x of
    True -> LB.singleton 1
    False -> LB.singleton 0
  UniversalValueInteger f _ -> error "write integer encoding"

data Person = Person
  { personName :: ByteString
  , personAge :: Integer
  , personConcern :: Concern
  }

data Concern
  = ConcernNumber Integer
  | ConcernSpeech String

data Human = Human
  { humanName :: Text
  , humanFirstWords :: Text
  , humanAge :: Age
  }

data Age = AgeBiblical Integer | AgeModern Integer

human :: Enc Human
human = sequence
  [ required "name" humanName utf8String
  , required "first-words" humanFirstWords utf8String
  , required "age" humanAge age
  ]

age :: Enc Age
age = choice [AgeBiblical 0, AgeModern 0] $ \x -> case x of
  AgeBiblical n -> option 0 "biblical" n $ tag 0 $ integerRanged 0 1000
  AgeModern n -> option 1 "modern" n $ tag 5 $ integerRanged 0 100
  

integerBE :: Integer -> LB.ByteString
integerBE i
  | i < 128 && i > (-129) = Builder.int8 (fromIntegral i)
  | otherwise = 
      let numberOfBits = integerLog2 i + 1
          unusedRes = quotRem numberOfBits 8
       in if i > 0
            then let r = goPos i
                  in if testBit (LB.head i)
            else 
  where
  goPos :: Integer -> Builder
  goPos n1 = let (!n2,!byteVal) = quotRem i 256
              in goPos n2 <> LB.singleton (fromIntegral byteVal)

integerLog2 :: Integer -> Int
integerLog2 i = I# (integerLog2# i)


