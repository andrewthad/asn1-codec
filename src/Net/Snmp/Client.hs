{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

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
import Data.Int
import Control.Concurrent
import Debug.Trace
import Text.Printf (printf)
import Data.Bits
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
  -- , sessionCredsTimestamps :: !(TVar (Map Word32
  , sessionSocketCount :: !Int
  , sessionRequestId :: !(TVar RequestId)
  , sessionAesSalt :: !(TVar AesSalt)
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

newtype CredentialsV2 = CredentialsV2
  { credentialsV2CommunityString :: ByteString }

data CredentialsV3 = CredentialsV3
  { credentialsV3Crypto :: !Crypto
  , credentialsV3ContextName :: !ByteString
  , credentialsV3User :: !ByteString
  }

data Context = Context
  { contextSession :: !Session
  , contextDestination :: !Destination
  , contextCredentials :: !Credentials
  }

data PerHostV3 = PerHostV3
  { perHostV3AuthoritativeEngineId :: !EngineId
  , perHostV3ReceiverTime :: !Int32
  , perHostV3ReceiverBoots :: !Int32
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
  aesSaltVar <- newTVarIO (AesSalt 1)
  socketChan <- newChan
  writeList2Chan socketChan allSockets
  return (Session socketChan socketPoolSize requestIdVar aesSaltVar timeout retries)

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
  sock <- readChan (sessionSockets session)
  case creds of
    CredentialsConstructV2 (CredentialsV2 commStr) -> do
      requestId <- nextRequestId (sessionRequestId session)
      let !bs = id
            $ LB.toStrict
            $ AsnEncoding.der SnmpEncoding.messageV2
            $ MessageV2 commStr
            $ pdusFromRequestId requestId
          !bsLen = ByteString.length bs
          go1 :: Int -> IO (Either SnmpException Pdu)
          go1 !n1 = if n1 > 0
            then do
              when inDebugMode $ putStrLn "Sending:"
              when inDebugMode $ putStrLn (hexByteStringInternal bs)
              bytesSentLen <- NSB.sendTo sock bs (NS.SockAddrInet (fromIntegral port) (NS.tupleToHostAddress ip))
              if bytesSentLen /= bsLen
                then return $ Left $ SnmpExceptionNotAllBytesSent bytesSentLen bsLen
                else do
                  let go2 mperHostV3 = do
                        (isReadyAction,deregister) <- threadWaitReadSTM (mySockFd sock)
                        delay <- registerDelay (sessionTimeoutMicroseconds session)
                        isContentReady <- atomically $ (isReadyAction $> True) <|> (fini delay $> False)
                        deregister
                        if not isContentReady
                          then go1 (n1 - 1)
                          else do
                            bsRecv <- NSB.recv sock 10000
                            when inDebugMode $ putStrLn "Received:"
                            when inDebugMode $ print bsRecv
                            if ByteString.null bsRecv
                              then return (Left SnmpExceptionSocketClosed)
                              else case AsnDecoding.ber SnmpDecoding.messageV2 bsRecv of
                                  Left err -> return (Left $ SnmpExceptionDecoding err)
                                  Right msg -> case messageV2Data msg of
                                    PdusResponse pdu@(Pdu respRequestId _ _ _) ->
                                      case compare requestId respRequestId of
                                        GT -> go2 mperHostV3
                                        EQ -> return (Right pdu)
                                        LT -> return $ Left $ SnmpExceptionMissedResponse requestId respRequestId
                                    _ -> return (Left (SnmpExceptionNonPduResponseV2 msg))
                  go2 Nothing
            else return $ Left SnmpExceptionTimeout
      e <- go1 (sessionMaxTries session)
      writeChan (sessionSockets session) sock
      case e >>= fromPdu of
        Left err -> throwIO err
        Right a -> return a
    CredentialsConstructV3 (CredentialsV3 crypto contextName user) -> do
      -- setting the reportable flags is very important
      -- for AuthPriv
      let flags = cryptoFlags crypto .|. 0x04
          mkAuthParams :: RequestId -> PerHostV3 -> (ByteString,ScopedPduData) -> ByteString
          mkAuthParams reqId phv3 privPair = case cryptoAuth crypto of
            Nothing -> ByteString.empty
            Just (AuthParameters typ password) -> 
              -- figure out a way to cache this
              let key = SnmpEncoding.passwordToKey typ password (perHostV3AuthoritativeEngineId phv3)
                  serializationWithoutAuth = makeBs (ByteString.replicate 12 0x00) reqId privPair phv3
               in SnmpEncoding.mkSign typ key serializationWithoutAuth
          mkPrivParams :: AesSalt -> RequestId -> PerHostV3 -> (ByteString,ScopedPduData)
          mkPrivParams theSalt reqId phv3 = case crypto of
            AuthPriv (AuthParameters authType authPass) (PrivParameters privType privPass) -> case privType of
              PrivTypeAes ->
                let (encrypted,actualSaltBs) = SnmpEncoding.aesEncrypt 
                      key
                      (perHostV3ReceiverBoots phv3)
                      (perHostV3ReceiverTime phv3)
                      theSalt
                      (LB.toStrict (AsnEncoding.der SnmpEncoding.scopedPdu spdu))
                 in (actualSaltBs,ScopedPduDataEncrypted encrypted)
              PrivTypeDes -> 
                let (encrypted,actualSaltBs) = SnmpEncoding.desEncrypt 
                      key
                      (perHostV3ReceiverBoots phv3)
                      (fromIntegral (getAesSalt theSalt))
                      -- (perHostV3ReceiverTime phv3)
                      (LB.toStrict (AsnEncoding.der SnmpEncoding.scopedPdu spdu))
                 in (actualSaltBs,ScopedPduDataEncrypted encrypted)
              where key = SnmpEncoding.passwordToKey authType privPass (perHostV3AuthoritativeEngineId phv3)
            _ -> (ByteString.empty,ScopedPduDataPlaintext spdu)
            where spdu = ScopedPdu (perHostV3AuthoritativeEngineId phv3) contextName (pdusFromRequestId reqId)
          makeBs :: ByteString -> RequestId -> (ByteString,ScopedPduData) -> PerHostV3 -> ByteString
          makeBs activeAuthParams reqId (activePrivParams,spdud) (PerHostV3 authoritativeEngineId receiverTime boots) = 
            let myMsg = MessageV3
                  (HeaderData reqId 1500 flags) -- making up a max size
                  (Usm authoritativeEngineId boots receiverTime user activeAuthParams activePrivParams)
                  spdud
                myMsg2 = myMsg
                -- myMsg2 = trace ("THE MESSAGE TO SEND: " ++ show myMsg) myMsg
             in LB.toStrict $ AsnEncoding.der SnmpEncoding.messageV3 $ myMsg2
          fullMakeBs :: AesSalt -> RequestId -> PerHostV3 -> ByteString
          fullMakeBs theSalt reqId phv3 =
            let privPair = mkPrivParams theSalt reqId phv3
                authParams = mkAuthParams reqId phv3 privPair
                newBs = makeBs authParams reqId privPair phv3
             in newBs
          go1 :: Int -> RequestId -> ByteString -> Bool -> IO (Either SnmpException Pdu)
          go1 !n1 !requestId !bsSent !engineIdsAcquired = if n1 > 0
            then do
              when inDebugMode $ putStrLn "Sending:"
              when inDebugMode $ putStrLn (hexByteStringInternal bsSent)
              let bsLen = ByteString.length bsSent
              bytesSentLen <- NSB.sendTo sock bsSent (NS.SockAddrInet (fromIntegral port) (NS.tupleToHostAddress ip))
              if bytesSentLen /= bsLen
                then return $ Left $ SnmpExceptionNotAllBytesSent bytesSentLen bsLen
                else do
                  let go2 :: IO (Either SnmpException Pdu)
                      go2 = do
                        (isReadyAction,deregister) <- threadWaitReadSTM (mySockFd sock)
                        delay <- registerDelay (sessionTimeoutMicroseconds session)
                        isContentReady <- atomically $ (isReadyAction $> True) <|> (fini delay $> False)
                        deregister
                        if not isContentReady
                          then do
                            when inDebugMode $ putStrLn "NO RESPONSE"
                            requestId' <- nextRequestId (sessionRequestId session)
                            go1 (n1 - 1) requestId' bsSent engineIdsAcquired
                          else do
                            bsRecv <- NSB.recv sock 10000
                            when inDebugMode $ putStrLn "Received:"
                            when inDebugMode $ putStrLn (hexByteStringInternal bsRecv)
                            if ByteString.null bsRecv
                              then return (Left SnmpExceptionSocketClosed)
                              else case AsnDecoding.ber SnmpDecoding.messageV3 bsRecv of
                                Left err -> return (Left $ SnmpExceptionDecoding err)
                                Right msg -> do
                                  case cryptoAuth crypto of
                                    Nothing -> return ()
                                    Just (AuthParameters typ password) -> do
                                      when inDebugMode $ putStrLn "THE RECEIVED MESSAGE"
                                      when inDebugMode $ print msg
                                      let reencoded = LB.toStrict $ AsnEncoding.der SnmpEncoding.messageV3 msg
                                      when inDebugMode $ putStrLn $ hexByteStringInternal $ reencoded
                                      when (reencoded /= bsRecv) $ do
                                        when inDebugMode $ putStrLn "NOT THE SAME"
                                      let key = SnmpEncoding.passwordToKey typ password (usmAuthoritativeEngineId (messageV3SecurityParameters msg))
                                      case SnmpEncoding.checkSign typ key msg of
                                        Nothing -> return ()
                                        Just (expected,actual) -> do
                                          when (not $ ByteString.null actual) $ do
                                            throwIO $ SnmpExceptionAuthenticationFailure expected actual
                                  let handleSpdu :: ScopedPdu -> IO (Either SnmpException Pdu)
                                      handleSpdu spdu = case scopedPduData spdu of 
                                        -- check to make sure that we requested an unencrypted response
                                        -- somehow check the message id in here too
                                        PdusResponse pdu@(Pdu respRequestId _ _ _) ->
                                          case compare requestId respRequestId of
                                            GT -> go2
                                            EQ -> return (Right pdu)
                                            LT -> return $ Left $ SnmpExceptionMissedResponse requestId respRequestId
                                        PdusReport (Pdu respRequestId _ _ _) -> do
                                          when inDebugMode $ putStrLn $ "Expected Request ID: " ++ show requestId
                                          when inDebugMode $ putStrLn $ "Received Request ID: " ++ show respRequestId
                                          let handleReport = if engineIdsAcquired
                                                then return $ Left (SnmpExceptionBadEngineId msg)
                                                else do
                                                  let usm = messageV3SecurityParameters msg
                                                      phv3 = PerHostV3
                                                        (usmAuthoritativeEngineId usm)
                                                        (usmAuthoritativeEngineTime usm)
                                                        (usmAuthoritativeEngineBoots usm)
                                                  theSalt <- atomically $ nextSalt (sessionAesSalt session)
                                                  requestId' <- nextRequestId (sessionRequestId session)
                                                  -- Notice that n1 is not decremented in this
                                                  -- situation. This is intentional.
                                                  go1 n1 requestId' (fullMakeBs theSalt requestId' phv3) True
                                          if respRequestId == RequestId 0
                                            then handleReport
                                            else case compare requestId respRequestId of
                                              GT -> go2
                                              EQ -> handleReport
                                              LT -> return $ Left $ SnmpExceptionMissedResponse requestId respRequestId
                                        _ -> return (Left (SnmpExceptionNonPduResponseV3 msg))
                                  case messageV3Data msg of
                                    ScopedPduDataEncrypted encrypted -> case crypto of
                                      AuthPriv (AuthParameters authType _) (PrivParameters privType privPass) -> do
                                        let usm = messageV3SecurityParameters msg
                                            key = SnmpEncoding.passwordToKey authType privPass (usmAuthoritativeEngineId usm)
                                            mdecrypted = case privType of
                                              PrivTypeDes -> SnmpEncoding.desDecrypt key (usmPrivacyParameters usm) encrypted
                                              PrivTypeAes -> SnmpEncoding.aesDecrypt key (usmPrivacyParameters usm) (usmAuthoritativeEngineBoots usm) (usmAuthoritativeEngineTime usm) encrypted
                                        case mdecrypted of
                                          Just bs -> case AsnDecoding.ber SnmpDecoding.scopedPdu bs of
                                            Left err -> throwIO (SnmpExceptionDecoding err)
                                            Right spdu -> handleSpdu spdu
                                          Nothing -> throwIO SnmpExceptionDecryptionFailure
                                    ScopedPduDataPlaintext spdu -> handleSpdu spdu 
                  go2
            else return $ Left SnmpExceptionTimeout
      -- boots and estimated time are made up for this, we could do better
      let originalPhv3 = PerHostV3 (EngineId "initial-engine-id") 0xFFFFFF 0xEEEEEE
      theSalt <- atomically $ nextSalt (sessionAesSalt session)
      requestId' <- nextRequestId (sessionRequestId session)
      e <- go1 (sessionMaxTries session) requestId' (fullMakeBs theSalt requestId' originalPhv3) False
      writeChan (sessionSockets session) sock
      case e >>= fromPdu of
        Left err -> throwIO err
        Right a -> return a

nextSalt :: TVar AesSalt -> STM AesSalt
nextSalt _ = return (AesSalt 0)

-- nextSalt :: TVar AesSalt -> STM AesSalt
-- nextSalt v = do
--   AesSalt w <- readTVar v
--   let s = AesSalt (w + 1)
--   writeTVar v s
--   return s

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
  | SnmpExceptionNonPduResponseV3 !MessageV3
  | SnmpExceptionDecoding !String
  | SnmpExceptionSocketClosed
  | SnmpExceptionAuthenticationFailure !ByteString !ByteString
  | SnmpExceptionBadEngineId !MessageV3
  | SnmpExceptionDecryptionFailure 
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
      !i3 = if i2 == 0 then 1 else i2
  writeTVar requestIdVar (RequestId i3)
  return (RequestId i3)

mySockFd :: NS.Socket -> System.Posix.Types.Fd
mySockFd (NS.MkSocket n _ _ _ _) = System.Posix.Types.Fd n

hexByteStringInternal :: ByteString -> String
hexByteStringInternal = ByteString.foldr (\w xs -> printf "%02X" w ++ xs) []

inDebugMode :: Bool
inDebugMode = False

