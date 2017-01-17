{-# LANGUAGE BangPatterns #-}

module Net.Snmp.Client where

import Net.Snmp.Types
import Language.Asn.Types
import Data.Coerce
import Control.Monad.STM
import Control.Concurrent.STM.TVar
import Control.Concurrent.STM.TMVar
import Data.Map (Map)
import Data.Maybe
import Data.Word
import Data.Vector (Vector)
import Data.IntMap (IntMap)
import Control.Monad
import Control.Concurrent (forkIO)
import Control.Concurrent.Chan
import Data.ByteString (ByteString)
import Control.Exception (throwIO,Exception)
import Control.Applicative
import Data.Functor
import Control.Concurrent
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
import qualified System.Posix.Types

data Session = Session
  { sessionSockets :: !(Chan NS.Socket)
  , sessionSocketCount :: !Int
  , sessionRequestId :: !(TVar RequestId)
  , sessionTimeoutMicroseconds :: !Int
  , sessionMaxTries :: !Int
  }

data Config = Config
  { configSocketPoolSize :: !Int
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

data Context = Context
  { contextSession :: !Session
  , contextDestination :: !Destination
  , contextCredentials :: !Credentials
  }

-- | Only one connection can be open at a time on a given port.
openSession :: Config -> IO Session
openSession (Config socketPoolSize timeout retries) = do
  addrinfos <- NS.getAddrInfo
    (Just (NS.defaultHints {NS.addrFlags = [NS.AI_PASSIVE]}))
    (Just "0.0.0.0")
    Nothing
  let serveraddr = head addrinfos
  allSockets <- replicateM socketPoolSize $ do
    sock <- NS.socket (NS.addrFamily serveraddr) NS.Datagram NS.defaultProtocol
    NS.bind sock (NS.addrAddress serveraddr)
    return sock
  requestIdVar <- newTVarIO (RequestId 1)
  socketChan <- newChan
  writeList2Chan socketChan allSockets
  return (Session socketChan socketPoolSize requestIdVar timeout retries)

closeSession :: Session -> IO ()
closeSession session = replicateM_ (sessionSocketCount session) $ do
  sock <- readChan (sessionSockets session)
  NS.close sock

generalRequest ::
     (RequestId -> Pdus)
  -> (Pdu -> Either SnmpException a)
  -> Context
  -> IO a
generalRequest pdusFromRequestId fromPdu (Context session (Destination ip port) creds) = do
  requestId <- nextRequestId (sessionRequestId session)
  receivedPduVar <- newEmptyTMVarIO
  sock <- readChan (sessionSockets session)
  let !bs = case creds of
        CredentialsConstructV2 (CredentialsV2 commStr) -> id
          $ LB.toStrict
          $ AsnEncoding.der SnmpEncoding.messageV2
          $ MessageV2 commStr
          $ pdusFromRequestId requestId
        CredentialsConstructV3 CredentialsV3 -> error "generalRequest: handle v3"
      !bsLen = ByteString.length bs
      go1 :: Int -> IO (Either SnmpException Pdu)
      go1 !n1 = if n1 > 0
        then do
          putStrLn $ "About to send: " ++ show bs
          bytesSent <- NSB.sendTo sock bs (NS.SockAddrInet (fromIntegral port) (NS.tupleToHostAddress ip))
          if bytesSent /= bsLen
            then return $ Left $ SnmpExceptionNotAllBytesSent bytesSent bsLen
            else do
              let go2 = do
                    (isReadyAction,deregister) <- threadWaitReadSTM (mySockFd sock)
                    delay <- registerDelay (sessionTimeoutMicroseconds session)
                    isContentReady <- atomically $ (isReadyAction $> True) <|> (fini delay $> False)
                    deregister
                    if not isContentReady
                      then go1 (n1 - 1)
                      else do
                        bs <- NSB.recv sock 10000
                        if ByteString.null bs
                          then return (Left SnmpExceptionSocketClosed)
                          else case AsnDecoding.ber SnmpDecoding.messageV2 bs of
                            Left err -> return (Left $ SnmpExceptionDecoding err)
                            Right msg -> case messageV2Data msg of
                              PdusResponse pdu@(Pdu respRequestId _ _ _) ->
                                case compare requestId respRequestId of
                                  LT -> go2
                                  EQ -> return (Right pdu)
                                  GT -> return $ Left $ SnmpExceptionMissedResponse requestId respRequestId
                              _ -> return (Left (SnmpExceptionNonPduResponseV2 msg))
              go2
        else return $ Left SnmpExceptionTimeout
  e <- go1 (sessionMaxTries session)
  writeChan (sessionSockets session) sock
  case e >>= fromPdu of
    Left err -> throwIO err
    Right a -> return a

get :: Context -> ObjectIdentifier -> IO ObjectSyntax
get ctx ident = generalRequest
  (\reqId -> PdusGetRequest (Pdu reqId (ErrorStatus 0) (ErrorIndex 0) (Vector.singleton (VarBind ident BindingResultUnspecified))))
  (singleBindingValue ident <=< onlyBindings)
  ctx

getBulkStep :: Context -> Int -> ObjectIdentifier -> IO (Vector (ObjectIdentifier,ObjectSyntax))
getBulkStep ctx maxRep ident = generalRequest
  (\reqId -> PdusGetBulkRequest (BulkPdu reqId 0 (fromIntegral maxRep) (Vector.singleton (VarBind ident BindingResultUnspecified))))
  (fmap multipleBindings . onlyBindings)
  ctx

getBulkChildren :: Context -> Int -> ObjectIdentifier -> IO (Vector (ObjectIdentifier,ObjectSyntax))
getBulkChildren ctx maxRep oid1 = go Vector.empty oid1 where
  go prevPairs ident = do
    pairsUnfiltered <- getBulkStep ctx maxRep ident
    let pairs = Vector.filter (\(oid,_) -> oidIsPrefixOf oid1 oid) pairsUnfiltered
    if Vector.null pairs
      then return prevPairs
      else go (prevPairs Vector.++ pairs) (fst (Vector.last pairs))

oidIsPrefixOf :: ObjectIdentifier -> ObjectIdentifier -> Bool
oidIsPrefixOf (ObjectIdentifier a) (ObjectIdentifier b) =
  let lenA = Vector.length a in
  (lenA <= Vector.length b) &&
  (a == Vector.take lenA b)

-- There is not a mapMaybe for vector until 0.12.0.0
multipleBindings :: Vector VarBind -> Vector (ObjectIdentifier,ObjectSyntax)
multipleBindings = Vector.fromList . mapMaybe
  ( \(VarBind ident br) -> case br of
       BindingResultValue obj -> Just (ident,obj)
       _ -> Nothing
  ) . Vector.toList

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
  | SnmpExceptionMissedResponse !RequestId !RequestId
  | SnmpExceptionNonPduResponseV2 !MessageV2
  | SnmpExceptionDecoding !String
  | SnmpExceptionSocketClosed
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

mySockFd :: NS.Socket -> System.Posix.Types.Fd
mySockFd (NS.MkSocket n _ _ _ _) = System.Posix.Types.Fd n

