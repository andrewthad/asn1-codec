module Language.Asn.ObjectIdentifier where

import Language.Asn.Types
import Data.Maybe
import qualified Data.Vector as Vector

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




