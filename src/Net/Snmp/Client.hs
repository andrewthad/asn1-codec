module Net.Snmp.Client where

import Net.Snmp.Types
import Data.Coerce
import qualified Network.Socket.ByteString as NSB
import qualified Net.Snmp.Decoding as SnmpDecoding
import qualified Language.Asn.Decoding as AsnDecoding

data Session = Session
  { sessionBufferedResponsesV2 :: TVar (Map RequestId (TMVar Pdu)))
  , sessionRequestId :: TVar RequestId
  , sessionTimeoutMicroseconds :: Int
  , sessionRetries :: Int
  }

data Config = Config
  { configPort :: Word16
  , configErrorHandler :: String -> IO ()
  , configTimeoutMicroseconds :: Int
  , configRetries :: Int
  }

-- | Only one connection can be open at a time on a given port.
openSession :: Config -> IO Session
openSession (Config port errHandler timeout retries) = do
  addrinfos <- getAddrInfo (Just (defaultHints {addrFlags = [AI_PASSIVE]})) Nothing (Just (show port))
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
  bufferedResponsesVar <- newTVarIO (Map.empty :: TVar (Map RequestId (TMVar Pdu)))
  requestIdVar <- newTVarIO (RequestId 1)
  bindSocket sock (addrAddress serveraddr)
  let go = do
        bs <- NSB.recv sock 10000
        if ByteString.null bs
          then return ()
          else do
            case AsnDecoding.ber SnmpDecoding.messageV2 bs of
              Left err -> errHandler err
              Right msg -> case messageV2Data msg of
                PdusResponse pdu@(Pdu requestId _ _ _) -> do
                  atomically $ do
                    bufferedResponses <- readTVar bufferedResponsesVar
                    case Map.lookup requestId bufferedResponses of
                      Nothing -> errHandler "the haskell snmp client has an implementation mistake. If you see this, please open an issue."
                      Just pduVar -> putTMVar pduVar pdu -- this should not ever block
                    let newBufferedResponses = Map.delete requestId bufferedResponses
                    writeTVar bufferedResponsesVar bufferedResponses
                _ -> errHandler "received a PDU that was not a response"
            go
  forkIO go
  return (Session bufferedResponsesVar requestIdVar timeout retries)

generalRequest :: (Pdu -> Pdus) -> (Pdu -> Either String a) -> Session -> Word32 -> Vector VarBind -> IO a
generalRequest wrapPdu fromPdu session ip varBinds = do
  requestId <- nextRequestId (sessionRequestId session)
  receivedPduVar <- newEmptyTMVarIO
  atomically $ modifyTVar'
    (sessionBufferedResponsesV2 session)
    (IntMap.insert (coerce requestId) receivedPduVar)

nextRequestId :: TVar RequestId -> IO RequestId
nextRequestId requestIdVar = atomically $ do
  RequestId i1 <- readTVar requestIdVar
  let !i2 = mod (i1 + 1) 100000000
  writeTVar requestIdVar i2
  return (RequestId i2)


