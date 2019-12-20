ECHO OFF
cls
ECHO RUNNING REF NAKOV FORWARD Client
java -jar ForwardClient.jar --handshakehost=localhost --handshakeport=2206 --targethost=localhost --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der
PAUSE