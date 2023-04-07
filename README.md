# Intrusion Detection System in Haskell
This is a simple Intrusion Detection System (IDS) written in Haskell that uses a signature-based approach to detect potential attacks. The program listens for incoming connections on port 3000 and spawns a new thread to handle each connection. When a message is received, it searches for the signature patterns defined in the signatures list using regular expressions. If a match is found, it prints a message indicating that an attack has been detected.

# Installation
To compile and run the program, you will need the Haskell compiler ghc and the network and regex-posix libraries installed on your system. You can install these using the Haskell package manager cabal:

cabal update

cabal install network regex-posix

Once you have installed the dependencies, you can compile the program using ghc:


ghc -o ids ids.hs

This will create an executable file called ids. You can then run the program using the following command:

bash
./ids

# Usage

To use the IDS, simply connect to the server on port 3000 using a TCP client such as telnet or netcat. The IDS will automatically detect any attacks based on the signature patterns defined in the signatures list.

# Limitations
This is a very simple IDS and is not suitable for production use. In practice, an IDS would use more sophisticated techniques such as anomaly detection, machine learning, and correlation of events across multiple systems to identify potential attacks. This example is intended to demonstrate the basic concepts involved in building an IDS in Haskell.

# License
This program is licensed under the MIT License. See the LICENSE file for details.

# Acknowledgments
This program was inspired by the following resources:

Building a Simple Intrusion Detection System in Python
Writing a Network Server in Haskell
Text.Regex.Posix documentation
