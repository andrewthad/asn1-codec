module Language.Asn.ObjectIdentifier where

import Language.Asn.Types
import Data.Maybe
import Data.Text (Text)
import Data.ByteString (ByteString)
import qualified Data.Text as Text
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as BC8
import qualified Data.Vector as Vector
import qualified Data.List as List

fromList :: [Integer] -> ObjectIdentifier
fromList = ObjectIdentifier . Vector.fromList

suffixSingleton :: Integer -> ObjectIdentifierSuffix
suffixSingleton = ObjectIdentifierSuffix . Vector.singleton

appendSuffix :: ObjectIdentifier -> ObjectIdentifierSuffix -> ObjectIdentifier
appendSuffix (ObjectIdentifier a) (ObjectIdentifierSuffix b) = ObjectIdentifier (a Vector.++ b)

isPrefixOf :: ObjectIdentifier -> ObjectIdentifier -> Bool
isPrefixOf a b = isJust (stripPrefix a b)

-- improve this later
stripPrefix :: ObjectIdentifier -> ObjectIdentifier -> Maybe ObjectIdentifierSuffix
stripPrefix (ObjectIdentifier a) (ObjectIdentifier b) =
  let lenA = Vector.length a
   in if (lenA <= Vector.length b) && (a == Vector.take lenA b)
        then Just (ObjectIdentifierSuffix (Vector.drop lenA b))
        else Nothing

encodeString :: ObjectIdentifier -> String
encodeString = List.intercalate "." . Vector.toList . Vector.map show . getObjectIdentifier

encodeByteString :: ObjectIdentifier -> ByteString
encodeByteString = BC8.pack . encodeString

encodeText :: ObjectIdentifier -> Text
encodeText = Text.pack . encodeString


