--Author: Ford Scott
-- Intrusion detection program
-- Monitors Port 3000 for incoming messages

import Control.Concurrent
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString.Char8 as C
import Data.List.Split (splitOn)
import Control.Monad (forever, forM_)

-- Define the signature patterns to search for
type Signature = (String, [String])
signatures :: [Signature]
signatures = [("XSS", ["<script>"]), ("SQLI", ["';", "--"])]

-- Tokenize the input
tokenize :: C.ByteString -> [String]
tokenize input = splitOn " " (C.unpack input)

-- Define a function to check for signatures in the tokenized input
checkForSignatures :: [String] -> [String]
checkForSignatures tokens = concatMap checkSignature signatures
  where checkSignature (name, patterns) =
          if any (`elem` tokens) patterns
          then [name ++ " attack detected"]
          else []

-- Define a function to process incoming messages and check for attacks
processMessage :: Socket -> IO ()
processMessage sock = do
  msg <- recv sock 1024
  let vulnerabilities = checkForSignatures (tokenize msg)
  if null vulnerabilities
    then putStrLn "No attacks detected"
    else mapM_ putStrLn vulnerabilities

-- Function to start listening on a given port
listenOnPort :: PortNumber -> IO ()
listenOnPort port = withSocketsDo $ do
  addrinfos <- getAddrInfo
               (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
               Nothing
               (Just $ show port)
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Stream defaultProtocol
  bind sock (addrAddress serveraddr)
  listen sock 5
  putStrLn $ "Server listening on port " ++ show port
  forever $ do
    (clientsock, clientaddr) <- accept sock
    putStrLn $ "Client connected: " ++ show clientaddr
    forkIO (processMessage clientsock)
    return ()

-- Main function to start the server on multiple ports
main :: IO ()
main = do
  let ports = [3000, 8080, 443] -- Add the list of ports you want to monitor
  forM_ ports $ \port ->
    forkIO $ listenOnPort (fromIntegral port)
  forever $ threadDelay 1000000 -- Prevents the main thread from exiting

