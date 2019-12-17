/**
 * ForwardServerClientThread handles the clients of Nakov Forward Server. It
 * connects two sockets and starts the TCP forwarding between given client
 * and its assigned server. After the forwarding is failed and the two threads
 * are stopped, closes the sockets.
 *
 */

/**
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 *
 * Peter Sjodin, KTH
 */

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

public class ForwardServerClientThread extends Thread
{
    private ForwardClient mForwardClient = null;
    private Socket mClientSocket = null;
    private Socket mServerSocket = null;
    private ServerSocket mListenSocket = null;
    private boolean mBothConnectionsAreAlive = false;
    private String mClientHostPort;
    private String mServerHostPort;
    private int mServerPort;
    private String mServerHost;
    private final boolean ENCRYPTED_SESSION;
    private SessionEncrypter mSessionEncrypter = null;
    private SessionDecrypter mSessionDecrypter = null;

    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * A client socket should be connected and passed to this constructor.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(Socket aClientSocket, String serverhost, int serverport)
    {
        mClientSocket = aClientSocket;
        mServerPort = serverport;
        mServerHost = serverhost;
        ENCRYPTED_SESSION = false;
    }

    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * Wait for client to connect on client listening socket.
     * A server socket is created later by run() method.
     */
    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport) throws IOException
    {
        mListenSocket = listensocket;
        //mServerHost =  listensocket.getInetAddress().getHostAddress();
        mServerPort = serverport;
        mServerHost = serverhost;
        ENCRYPTED_SESSION = false;
    }

    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * A client socket should be connected and passed to this constructor.
     * A server socket is created later by run() method.
     * SUPPORTS ENCRYPTED SESSIONS
     */
    public ForwardServerClientThread(Socket aClientSocket, String serverhost, int serverport, SessionEncrypter aSessionEncrypter, SessionDecrypter aSessionDecrypter)
    {
        mClientSocket = aClientSocket;
        mServerPort = serverport;
        mServerHost = serverhost;
        mSessionEncrypter = aSessionEncrypter;
        mSessionDecrypter = aSessionDecrypter;
        ENCRYPTED_SESSION = true;
    }
 
    /**
     * Creates a client thread for handling clients of NakovForwardServer.
     * Wait for client to connect on client listening socket.
     * A server socket is created later by run() method.
     * SUPPORTS ENCRYPTED SESSIONS
     */
    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport, SessionEncrypter aSessionEncrypter, SessionDecrypter aSessionDecrypter) throws IOException
    {
        mListenSocket = listensocket;
        //mServerHost =  listensocket.getInetAddress().getHostAddress();
        mServerPort = serverport;
        mServerHost = serverhost;
        mSessionEncrypter = aSessionEncrypter;
        mSessionDecrypter = aSessionDecrypter;
        ENCRYPTED_SESSION = true;
    }

    public ServerSocket getListenSocket() {
        return mListenSocket;
    }

    /**
     * Obtains a destination server socket to some of the servers in the list.
     * Starts two threads for forwarding : "client in <--> dest server out" and
     * "dest server in <--> client out", waits until one of these threads stop
     * due to read/write failure or connection closure. Closes opened connections.
     * 
     * If there is a listen socket, first wait for incoming connection
     * on the listen socket.
     */
    public void run()
    {
        try {
 
            // Wait for incoming connection on listen socket, if there is one 
           if (mListenSocket != null) {
               mClientSocket = mListenSocket.accept();
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
               Logger.log("Accepted from  " + mServerPort + " <--> " + mClientHostPort + "  started.");
               
           }
           else {
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
           }

           try {
               mServerSocket = new Socket(mServerHost, mServerPort);
           } catch (Exception e) {
               System.out.println("Connection failed to " + mServerHost + ":" + mServerPort);
               e.printStackTrace(); 
               // Prints what exception has been thrown 
               System.out.println(e); 
           }

            InputStream clientIn;
            OutputStream clientOut;
            InputStream serverIn;
            OutputStream serverOut;
            // If session is encrypted, encrypt and decrypt the streams
            if (ENCRYPTED_SESSION) {
                clientIn = mSessionDecrypter.openCipherInputStream(mClientSocket.getInputStream());
                clientOut = mSessionEncrypter.openCipherOutputStream(mClientSocket.getOutputStream());
                serverIn = mSessionDecrypter.openCipherInputStream(mServerSocket.getInputStream());
                serverOut = mSessionEncrypter.openCipherOutputStream(mServerSocket.getOutputStream());
            } else {
                clientIn = mClientSocket.getInputStream();
                clientOut = mClientSocket.getOutputStream();
                serverIn = mServerSocket.getInputStream();
                serverOut = mServerSocket.getOutputStream();
            }

           mServerHostPort = mServerHost + ":" + mServerPort;
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  started.");

           // Start forwarding of socket data between server and client
           ForwardThread clientForward= new ForwardThread(this, clientIn, serverOut);
           ForwardThread serverForward = new ForwardThread(this, serverIn, clientOut);
           mBothConnectionsAreAlive = true;
           clientForward.start();
           serverForward.start();
 
        } catch (IOException ioe) {
           ioe.printStackTrace();
        }
    }
 
    /**
     * connectionBroken() method is called by forwarding child threads to notify
     * this thread (their parent thread) that one of the connections (server or client)
     * is broken (a read/write failure occured). This method disconnects both server
     * and client sockets causing both threads to stop forwarding.
     */
    public synchronized void connectionBroken() {
        if (mBothConnectionsAreAlive) {
           // One of the connections is broken. Close the other connection and stop forwarding
           // Closing these socket connections will close their input/output streams
           // and that way will stop the threads that read from these streams
           try { mServerSocket.close(); } catch (IOException e) { System.err.println(e.getMessage()); }
           try { mClientSocket.close(); } catch (IOException e) { System.err.println(e.getMessage()); }
 
           mBothConnectionsAreAlive = false;
 
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  stopped.");
        }
    }
 
}
