{-# LANGUAGE BangPatterns #-}

module Net.Snmp.Client where

import Net.Snmp.Types
import Language.Asn.Types
import Data.Coerce
import Control.Monad.STM
import Control.Concurrent.STM.TVar
import Control.Concurrent.STM.TMVar
import Data.Map (Map)
import Data.Word
import Data.Vector (Vector)
import Data.IntMap (IntMap)
import Control.Monad
import Control.Concurrent (forkIO)
import Data.ByteString (ByteString)
import Control.Exception (throwIO,Exception)
import Control.Applicative
import qualified Data.Vector as Vector
import qualified Data.IntMap as IntMap
import qualified Network.Socket as NS
import qualified Data.ByteString as ByteString
import qualified Network.Socket.ByteString as NSB
import qualified Net.Snmp.Decoding as SnmpDecoding
import qualified Net.Snmp.Encoding as SnmpEncoding
import qualified Language.Asn.Decoding as AsnDecoding
import qualified Language.Asn.Encoding as AsnEncoding
import qualified Data.Map as Map
import qualified Data.ByteString.Lazy as LB

data Session = Session
  { sessionBufferedResponsesV2 :: TVar (IntMap (TMVar Pdu))
  , sessionSockets :: !(Chan NS.Socket)
  , sessionRequestId :: TVar RequestId
  , sessionTimeoutMicroseconds :: !Int
  , sessionMaxTries :: !Int
  }

data Config = Config
  { configSocketPoolSize :: !Int
  , configErrorHandler :: String -> IO ()
  , configTimeoutMicroseconds :: !Int
  , configRetries :: !Int
  }

data Destination = Destination
  { destinationHost :: !(Word8,Word8,Word8,Word8)
  , destinationPort :: !Word16
  }

data Credentials
  = CredentialsConstructV2 CredentialsV2
  | CredentialsConstructV3 CredentialsV3

newtype CredentialsV2 = CredentialsV2 { credentialsV2CommunityString :: ByteString }

data CredentialsV3 = CredentialsV3

-- | Only one connection can be open at a time on a given port.
openSession :: Config -> IO Session
openSession (Config socketPoolSize errHandler timeout retries) = do
  addrinfos <- NS.getAddrInfo (Just (NS.defaultHints {NS.addrFlags = [NS.AI_PASSIVE]})) (Just "127.0.0.1") Nothing
  let serveraddr = head addrinfos
  allSockets <- replicateM $ do
    sock <- NS.socket (NS.addrFamily serveraddr) NS.Datagram NS.defaultProtocol
    NS.bind sock (NS.addrAddress serveraddr)
    return sock
  bufferedResponsesVar <- newTVarIO (IntMap.empty :: IntMap (TMVar Pdu))
  requestIdVar <- newTVarIO (RequestId 1)
  socketChan <- newChan
  writeList2Chan socketChan allSockets
  let go = do
        bs <- NSB.recv sock 10000
        errHandler "Received a byte string"
        if ByteString.null bs
          then return ()
          else do
            case AsnDecoding.ber SnmpDecoding.messageV2 bs of
              Left err -> errHandler err
              Right msg -> case messageV2Data msg of
                PdusResponse pdu@(Pdu requestId _ _ _) -> do
                  hasError <- atomically $ do
                    bufferedResponses <- readTVar bufferedResponsesVar
                    case IntMap.lookup (getRequestId requestId) bufferedResponses of
                      Nothing -> return True
                      Just pduVar -> do
                        putTMVar pduVar pdu -- this should not ever block
                        let newBufferedResponses = IntMap.delete (getRequestId requestId) bufferedResponses
                        writeTVar bufferedResponsesVar bufferedResponses
                        return False
                  when hasError $ errHandler "the haskell snmp client has an implementation mistake. If you see this, please open an issue."
                _ -> errHandler $ "received a PDU that was not a response, full message: " ++ show msg
            go
  forkIO go
  return (Session bufferedResponsesVar sock requestIdVar timeout retries)

closeSession :: Session -> IO ()
closeSession session = NS.close (sessionSocket session)

generalRequest ::
     (Pdu -> Pdus) -> (Pdu -> Either SnmpException a)
  -> Session -> Destination -> Credentials -> Vector VarBind -> IO a
generalRequest wrapPdu fromPdu session (Destination ip port) creds varBinds = do
  requestId <- nextRequestId (sessionRequestId session)
  receivedPduVar <- newEmptyTMVarIO
  atomically $ modifyTVar'
    (sessionBufferedResponsesV2 session)
    (IntMap.insert (getRequestId requestId) receivedPduVar)
  let !bs = case creds of
        CredentialsConstructV2 (CredentialsV2 commStr) -> id
          $ LB.toStrict
          $ AsnEncoding.der SnmpEncoding.messageV2
          $ MessageV2 commStr
          $ wrapPdu
          $ Pdu requestId (ErrorStatus 0) (ErrorIndex 0) varBinds
        CredentialsConstructV3 CredentialsV3 -> error "generalRequest: handle v3"
      !bsLen = ByteString.length bs
      go !n1 = if n1 > 0
        then do
          putStrLn "about to send bytes"
          bytesSent <- NSB.sendTo (sessionSocket session) bs (NS.SockAddrInet (fromIntegral port) (NS.tupleToHostAddress ip))
          putStrLn "sent some bytes"
          when (bytesSent /= bsLen)
            $ throwIO $ SnmpExceptionNotAllBytesSent bytesSent bsLen
          m <- readTMVarTimeout (sessionTimeoutMicroseconds session) receivedPduVar
          case m of
            Nothing -> go (n1 - 1)
            Just pdu -> case fromPdu pdu of
              Left err -> throwIO err
              Right a -> return a
        else throwIO SnmpExceptionTimeout
        bs <- NSB.recv sock 10000
        errHandler "Received a byte string"
        if ByteString.null bs
          then return ()
          else do
            case AsnDecoding.ber SnmpDecoding.messageV2 bs of
              Left err -> errHandler err
              Right msg -> case messageV2Data msg of
                PdusResponse pdu@(Pdu requestId _ _ _) -> do
                  hasError <- atomically $ do
                    bufferedResponses <- readTVar bufferedResponsesVar
                    case IntMap.lookup (getRequestId requestId) bufferedResponses of
                      Nothing -> return True
                      Just pduVar -> do
                        putTMVar pduVar pdu -- this should not ever block
                        let newBufferedResponses = IntMap.delete (getRequestId requestId) bufferedResponses
                        writeTVar bufferedResponsesVar bufferedResponses
                        return False
                  when hasError $ errHandler "the haskell snmp client has an implementation mistake. If you see this, please open an issue."
                _ -> errHandler $ "received a PDU that was not a response, full message: " ++ show msg
            go
  go (sessionMaxTries session)

get :: Session -> Destination -> Credentials -> ObjectIdentifier -> IO ObjectSyntax
get s d c ident = generalRequest
  PdusGetRequest
  (singleBindingValue ident <=< onlyBindings)
  s d c
  (Vector.singleton (VarBind ident BindingResultUnspecified))

singleBindingValue :: ObjectIdentifier -> Vector VarBind -> Either SnmpException ObjectSyntax
singleBindingValue oid v = if Vector.length v == 1
  then do
    let VarBind name res = v Vector.! 0
    when (name /= oid) $ Left $ SnmpExceptionMismatchedBinding oid name
    case res of
      BindingResultValue obj -> Right obj
      BindingResultUnspecified -> Left SnmpExceptionUnspecified
      BindingResultNoSuchObject -> Left SnmpExceptionNoSuchObject
      BindingResultNoSuchInstance -> Left SnmpExceptionNoSuchInstance
      BindingResultEndOfMibView -> Left SnmpExceptionEndOfMibView
  else Left (SnmpExceptionMultipleBindings (Vector.length v))

onlyBindings :: Pdu -> Either SnmpException (Vector VarBind)
onlyBindings (Pdu _ errStatus@(ErrorStatus e) errIndex bindings) =
  if e == 0 then Right bindings else Left (SnmpExceptionPduError errStatus errIndex)

data SnmpException
  = SnmpExceptionNotAllBytesSent !Int !Int
  | SnmpExceptionTimeout
  | SnmpExceptionPduError !ErrorStatus !ErrorIndex
  | SnmpExceptionMultipleBindings !Int
  | SnmpExceptionMismatchedBinding !ObjectIdentifier !ObjectIdentifier
  | SnmpExceptionUnspecified -- ^ Should not happen
  | SnmpExceptionNoSuchObject
  | SnmpExceptionNoSuchInstance
  | SnmpExceptionEndOfMibView
  deriving (Show,Eq)

instance Exception SnmpException

readTMVarTimeout :: Int -> TMVar a -> IO (Maybe a)
readTMVarTimeout timeoutAfter pktChannel = do
  delay <- registerDelay timeoutAfter
  atomically $
        Just <$> readTMVar pktChannel
    <|> pure Nothing <* fini delay

fini :: TVar Bool -> STM ()
fini = check <=< readTVar

nextRequestId :: TVar RequestId -> IO RequestId
nextRequestId requestIdVar = atomically $ do
  RequestId i1 <- readTVar requestIdVar
  let !i2 = mod (i1 + 1) 100000000
  writeTVar requestIdVar (RequestId i2)
  return (RequestId i2)


