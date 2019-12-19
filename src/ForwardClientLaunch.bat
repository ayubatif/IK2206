ECHO OFF
cls
ECHO RUNNING NAKOV FORWARD Client
javac ForwardClient.java
java ForwardClient --handshakehost=localhost --handshakeport=2206 --targethost=localhost --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der
PAUSE