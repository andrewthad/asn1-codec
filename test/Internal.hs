module Internal where

import Data.Aeson.TH
import Data.Aeson.Types (camelTo2)

myOptions :: String -> Options
myOptions name = defaultOptions
  { fieldLabelModifier = camelTo2 '_' . drop (length name)
  , constructorTagModifier = camelTo2 '_' . drop (length name)
  }

