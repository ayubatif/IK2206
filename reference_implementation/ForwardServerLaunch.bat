ECHO OFF
cls
ECHO RUNNING REF NAKOV FORWARD SERVER
java -jar ForwardServer.jar --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der
PAUSE