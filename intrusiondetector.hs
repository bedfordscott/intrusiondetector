--Author: Ford Scott
-- Intrusion detection program
-- Monitors Port 3000 for incoming messages

import Control.Concurrent
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString.Char8 as C
import Text.Regex.Posix

-- Define the signature patterns to search for
type Signature = (String, String)
signatures :: [Signature]
signatures = [("XSS", "<script>"), ("SQLI", "';.*--")]

-- Define a function to check for signatures in the input
checkForSignatures :: C.ByteString -> [String]
checkForSignatures input = concatMap checkSignature signatures
  where checkSignature (name, pattern) =
          let matches = C.unpack input =~ pattern :: AllTextMatches [] String
          in if null matches
             then []
             else [name ++ " attack detected"]

-- Define a function to process incoming messages and check for attacks
processMessage :: Socket -> IO ()
processMessage sock = do
  msg <- recv sock 1024
  let vulnerabilities = checkForSignatures msg
  if null vulnerabilities
    then putStrLn "No attacks detected"
    else mapM_ putStrLn vulnerabilities

-- Define a function to listen for incoming connections and spawn new threads to handle them
startServer :: IO ()
startServer = withSocketsDo $ do
  addrinfos <- getAddrInfo (Just (defaultHints {addrFlags = [AI_PASSIVE]})) Nothing (Just "3000")
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Stream defaultProtocol
  bind sock (addrAddress serveraddr)
  listen sock 5
  putStrLn "Server started"
  forever $ do
    (clientsock, clientaddr) <- accept sock
    putStrLn $ "Client connected: " ++ show clientaddr
    forkIO (processMessage clientsock)
    return ()

-- Define the entry point for the program
main :: IO ()
main = startServer
