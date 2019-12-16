/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.io.*;
import java.lang.AssertionError;
import java.lang.Integer;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Properties;
import java.util.StringTokenizer;
 
public class ForwardServer {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";

    private static Arguments arguments;

    private ServerSocket handshakeSocket;
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws Exception {

        /* Check user cert */
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        InputStream in_cert_USER = new FileInputStream(arguments.get("usercert"));
        X509Certificate cert_USER = (X509Certificate) certFactory.generateCertificate(in_cert_USER);
        in_cert_USER.close();

        InputStream in_cert_CA = new FileInputStream(arguments.get("cacert"));
        X509Certificate cert_CA = (X509Certificate) certFactory.generateCertificate(in_cert_CA);
        in_cert_CA.close();

        VerifyCertificate.validate(cert_USER);
        VerifyCertificate.validate(cert_CA);
        VerifyCertificate.verify(cert_CA, cert_USER);

        /* Setup the socket */
        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        /* Encode the user cert */
        byte[] cert_USER_bytes64 = Base64.getEncoder().encode(cert_USER.getEncoded());
        String cert_USER_string64 = new String(cert_USER_bytes64);

        /* Now that server certs are OK, we check the incoming Handshake ClientHello msg by verifying its cert */
        HandshakeMessage cHelloMsg = new HandshakeMessage();
        cHelloMsg.recv(clientSocket);

        byte[] cert_CLIENT_bytes = Base64.getDecoder().decode(cHelloMsg.getParameter("Certificate"));
        X509Certificate cert_CLIENT = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(cert_CLIENT_bytes));

        VerifyCertificate.validate(cert_CLIENT);
        VerifyCertificate.verify(cert_CA, cert_CLIENT);

        /* With the client verified, we respond with a ServerHello msg */
        HandshakeMessage sHelloMsg = new HandshakeMessage();
        sHelloMsg.putParameter("MessageType", "ServerHello"); // Specify the message type
        sHelloMsg.putParameter("Certificate", cert_USER_string64); // Provide the cert
        sHelloMsg.send(clientSocket);

        /* When a Forward msg is received from the client, we prepare a Session msg */
        HandshakeMessage frwrdMsg = new HandshakeMessage();
        frwrdMsg.recv(clientSocket);

        /* Initialize session data */
        int keylength = 128;
        SessionKey sessionKey = new SessionKey(keylength);
        byte[] sessionIV = new byte[keylength/8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(sessionIV);

        /* Encrypt the binary data */
        byte[] sessionKey_bytes_encrypted = HandshakeCrypto.encrypt(sessionKey.getSecretKey().getEncoded(), cert_USER.getPublicKey());
        byte[] sessionIV_bytes_encrypted = HandshakeCrypto.encrypt(sessionIV, cert_USER.getPublicKey());

        /* Encode the encrypted binary data */
        byte[] sessionKey_bytes_encrypted64 = Base64.getEncoder().encode(sessionKey_bytes_encrypted);
        byte[] sessionIV_bytes_encrypted64 = Base64.getEncoder().encode(sessionIV_bytes_encrypted);

        /* Send the Session msg */
        HandshakeMessage sessionMsg = new HandshakeMessage();
        sessionMsg.put("MessageType", "Session");
        sessionMsg.put("SessionKey", new String(sessionKey_bytes_encrypted64));
        sessionMsg.put("SessionIV", new String(sessionIV_bytes_encrypted64));
        sessionMsg.put("SessionHost", frwrdMsg.getParameter("TargetHost"));
        sessionMsg.put("SessionPort", frwrdMsg.getParameter("TargetPort"));
        sessionMsg.send(clientSocket);

        /* Handshake complete */
        clientSocket.close();

        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(DEFAULTSERVERHOST, DEFAULTSERVERPORT));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = frwrdMsg.getParameter("TargetHost");
        targetPort = Integer.parseInt(frwrdMsg.getParameter("TargetPort"));
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;

            doHandshake();

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
            forwardThread.start();
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);

        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
 
}
