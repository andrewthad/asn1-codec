module Encode where

import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Builder as Builder
import Data.ByteString.Builder (Builder)
import Data.ByteString.Lazy (ByteString)
import Data.Vector (Vector)
import Data.Functor.Contravariant
import Data.Monoid
import Data.Int
-- import Data.ByteString.Builder (Builder)

data TagClass
  = TagClassUniversal
  | TagClassApplication
  | TagClassPrivate
  | TagClassContextSpecific

data Tag = Tag
  { tagClass :: TagClass
  , tagNumber :: Int
  }

data FieldEncoding a
  = FieldEncodingRequired (Encoding a)
  | FieldEncodingOptional (EncodingOptional a)

newtype Encoding a = Encoding (a -> Value)
newtype EncodingOptional a = EncodingOptional (a -> Maybe Value)

instance Contravariant Encoding where
  contramap f (Encoding g) = Encoding (g . f)

instance Contravariant EncodingOptional where
  contramap f (EncodingOptional g) = EncodingOptional (g . f)

data Retag = Explicit Tag | Implicit Tag | Tagless

data Value = Value Tag ByteString

-- data Age = AgeAncient Int | AgeModern Int

-- age :: Encoding Age
-- age =

required :: String -> Retag -> (b -> a) -> Encoding a -> FieldEncoding b
required _ r getter = FieldEncodingRequired . retag r . contramap getter

optional :: String -> Retag -> (b -> Maybe a) -> Encoding a -> FieldEncoding b
optional _ r getter = FieldEncodingOptional . contramap getter . encodingToOptional . retag r

sequence :: [FieldEncoding a] -> Encoding a
sequence encs = Encoding $ \a -> Value sequenceTag
  ( foldMap (\fe -> case fe of
      FieldEncodingRequired (Encoding f) -> encodeValue (f a)
      FieldEncodingOptional (EncodingOptional f) -> maybe LB.empty encodeValue (f a)
    ) encs
  )

sequenceTag :: Tag
sequenceTag = Tag TagClassUniversal 16

implicit :: Tag -> Encoding a -> Encoding a
implicit t (Encoding f) = Encoding (implicitTag t . f)

explicit :: Tag -> Encoding a -> Encoding a
explicit t (Encoding f) = Encoding (explicitTag t . f)

encodingToOptional :: Encoding a -> EncodingOptional (Maybe a)
encodingToOptional (Encoding f) = EncodingOptional (fmap f)

retag :: Retag -> Encoding a -> Encoding a
retag r e@(Encoding f) = case r of
  Implicit t -> Encoding (implicitTag t . f)
  Explicit t -> Encoding (explicitTag t . f)
  Tagless -> e

implicitTag :: Tag -> Value -> Value
implicitTag t (Value _ bs) = Value t bs

explicitTag :: Tag -> Value -> Value
explicitTag t v = Value t (encodeValue v)

encodeValue :: Value -> ByteString
encodeValue (Value t bs) = Builder.toLazyByteString (builderTag t <> builderLength (LB.length bs)) <> bs

builderTag :: Tag -> Builder
builderTag = error "hutnhutoboe"

builderLength :: Int64 -> Builder
builderLength = error "hutnoehtoenuh"



