{-# LANGUAGE OverloadedStrings #-}

module TestNetwork where

import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString
import Net.Snmp.Types
import Net.Snmp.Encoding
import Data.ByteString (ByteString)
import Recode
import Text.Printf (printf)
import Network.BSD (getProtocolNumber)
import Control.Concurrent
import Control.Monad
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LB
import qualified Data.Vector as Vector

printResponse :: MessageV2 -> IO ()
printResponse msg = do
  addrinfos <- getAddrInfo Nothing (Just "10.10.10.1") (Just "161")
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Stream defaultProtocol
  connect sock (addrAddress serveraddr)
  sendAll sock (LB.toStrict (encodeBer messageV2 msg))
  result <- recv sock 2048
  close sock
  putStrLn (hexByteString result)

sendUdp :: MessageV2 -> IO ()
sendUdp msg = do
  addrinfos <- getAddrInfo Nothing (Just "10.10.10.1") (Just "161")
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
  connect sock (addrAddress serveraddr)
  putStrLn "Sending"
  sendAll sock (LB.toStrict $ encodeBer messageV2 msg)
  msg <- recv sock 1024
  close sock
  putStr "Got response: "
  putStrLn (hexByteString msg)

backgroundListenUdp :: IO ()
backgroundListenUdp = void $ forkIO listenUdp

listenUdp :: IO ()
listenUdp = do
  protoNum <- getProtocolNumber "UDP"
  serveraddr:_ <- getAddrInfo
    (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
    Nothing (Just "161")
  sock <- socket (addrFamily serveraddr) Datagram protoNum
  bind sock (addrAddress serveraddr)
  let go = do
        (bs,_) <- recvFrom sock 4096
        if ByteString.null bs
          then close sock
          else putStrLn (hexByteString bs) >> go
  go

getSystemDescription :: MessageV2
getSystemDescription = MessageV2 "opsview"
  $ PdusGetRequest $ Pdu
    (RequestId 10000)
    (ErrorStatus 0)
    (ErrorIndex 0)
    $ Vector.singleton $ VarBind sysDescr BindingResultUnspecified

sysDescr :: ObjectIdentifier
sysDescr = ObjectIdentifier $ Vector.fromList [1,3,6,1,2,1,1,1,0]

hexByteString :: ByteString -> String
hexByteString = ByteString.foldr (\w xs -> printf "%02X" w ++ xs) []
