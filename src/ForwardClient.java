/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardClient {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static CertificateFactory certFactory;
    private static X509Certificate cert_CA;
    private static X509Certificate cert_USER;
    private static X509Certificate cert_SERVER;

    private static int serverPort;
    private static String serverHost;
    private static SessionEncrypter mSessionEncrypter;
    private static SessionDecrypter mSessionDecrypter;

    private static void doHandshake() throws Exception {

        /* Connect to forward server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        ForwardServerClientThread thread = new ForwardServerClientThread(socket, serverHost, serverPort);

        /* Encode the user cert */
        byte[] cert_USER_bytes64 = Base64.getEncoder().encode(cert_USER.getEncoded());
        String cert_USER_string64 = new String(cert_USER_bytes64);

        /* Now that client certs are OK, we start the Handshake with a Hello msg to the server */
        HandshakeMessage cHelloMsg = new HandshakeMessage();
        cHelloMsg.putParameter("MessageType", "ClientHello"); // Specify the message type
        cHelloMsg.putParameter("Certificate", cert_USER_string64); // Provide the cert
        cHelloMsg.send(socket);

        /* Now that server certs are OK, we check the incoming Handshake ClientHello msg by verifying its cert */
        HandshakeMessage sHelloMsg = new HandshakeMessage();
        sHelloMsg.recv(socket);

        byte[] cert_SERVER_bytes = Base64.getDecoder().decode(sHelloMsg.getParameter("Certificate"));
        cert_SERVER = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(cert_SERVER_bytes));

        VerifyCertificate.validate(cert_SERVER);
        VerifyCertificate.verify(cert_CA, cert_SERVER);

        /* With the server verified, we respond with a Forward Request msg */
		HandshakeMessage frwrdMsg = new HandshakeMessage();
        frwrdMsg.put("MessageType", "Forward"); // Specify the message type
        frwrdMsg.putParameter("TargetHost", arguments.get("targethost"));
        frwrdMsg.putParameter("TargetPort", arguments.get("targetport"));
        frwrdMsg.send(socket);

        /* With a Session msg received, the key and IV are stored */
        HandshakeMessage sessionMsg = new HandshakeMessage();
        sessionMsg.recv(socket);
        String sessionHost = sessionMsg.getParameter("SessionHost");
        int sessionPort = Integer.parseInt(sessionMsg.getParameter("SessionPort"));
        byte[] sessionKey_encrypted = Base64.getDecoder().decode(sessionMsg.getParameter("SessionKey"));
        byte[] sessionIV_encrypted = Base64.getDecoder().decode(sessionMsg.getParameter("SessionIV"));
        PrivateKey privatekey_USER = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
        mSessionEncrypter = new SessionEncrypter(HandshakeCrypto.decrypt(sessionKey_encrypted, privatekey_USER), HandshakeCrypto.decrypt(sessionIV_encrypted, privatekey_USER));
        mSessionDecrypter = new SessionDecrypter(mSessionEncrypter.getKeyBytes(), mSessionEncrypter.getIVBytes());

        /* Handshake complete */
        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
        serverHost = sessionHost;
        serverPort = sessionPort;
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null); 
        /* Tell the user, so the user knows where to connect */ 
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);
            
        forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, mSessionEncrypter, mSessionDecrypter);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }

    private static void checkCertificates() throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        certFactory = CertificateFactory.getInstance("X.509");

        InputStream in_USER = new FileInputStream(arguments.get("usercert"));
        cert_USER = (X509Certificate) certFactory.generateCertificate(in_USER);
        in_USER.close();

        InputStream in_CA = new FileInputStream(arguments.get("cacert"));
        cert_CA = (X509Certificate) certFactory.generateCertificate(in_CA);
        in_CA.close();

        VerifyCertificate.validate(cert_USER);
        VerifyCertificate.validate(cert_CA);
        VerifyCertificate.verify(cert_CA, cert_USER);
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws Exception {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        checkCertificates();
        startForwardClient();
    }
}
