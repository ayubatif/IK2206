ECHO OFF
cls
ECHO RUNNING NAKOV FORWARD SERVER
javac ForwardServer.java
java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der
PAUSE