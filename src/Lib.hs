{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

module Lib where

import Data.Vinyl.Types
import Data.Functor.Identity
import Text.Read (readMaybe)

data Asn a where
  AsnChoice :: Rec ChoiceField xs -> Asn (CoRec Asn xs)
  AsnSequence :: Rec SequenceField xs -> Asn (Rec Asn xs)
  AsnPrimitive :: Tag -> (String -> Maybe a) -> (a -> String) -> Asn a
  AsnDefault :: a -> Asn a -> Asn a

data SequenceField a = SequenceField
  { sequenceFieldName :: String
  , sequenceFieldTag :: Maybe Tag
  , sequenceFieldInclusion :: Inclusion
  , sequenceFieldDefault :: Maybe a
  , sequenceFieldValue :: Asn a
  }

data ChoiceField a = ChoiceField
  { choiceFieldName :: String
  , choiceFieldTag :: Maybe Tag
  , choiceFieldInclusion :: Inclusion
  , choiceFieldValue :: Asn a
  }

data Inclusion = Explicit | Implicit

data Tag = Tag
  { tagClass :: TagClass
  , tagNumber :: Int
  , tagDescription :: Maybe String
  }

data TagClass
  = TagClassUniversal
  | TagClassApplication
  | TagClassPrivate
  | TagClassContextSpecific

type Human f = Rec f '[String,String,Age f]
type Age f = CoRec f '[Int,Int]

int :: Asn Int
int = AsnPrimitive
  (Tag TagClassUniversal 2 (Just "INTEGER")) readMaybe show

utf8String :: Asn String
utf8String = AsnPrimitive
  (Tag TagClassUniversal 12 (Just "UTF8String")) Just id

example :: Asn (Human Asn)
example = AsnSequence $
     (SequenceField "name" Nothing Implicit Nothing utf8String)
  :& (SequenceField "first-words" Nothing Implicit (Just "Hello World") utf8String)
  :& (SequenceField "age" Nothing Implicit Nothing $ AsnChoice $
       ChoiceField "biblical" (Just $ Tag TagClassContextSpecific 3 Nothing) Implicit int
    :& ChoiceField "modern" (Just $ Tag TagClassContextSpecific 4 Nothing) Implicit int
    :& RNil
     )
  :& RNil

someFunc :: IO ()
someFunc = putStrLn "someFunc"
