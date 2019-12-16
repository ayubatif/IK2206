import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.cert.*;
import java.util.Base64;
import java.util.HashMap;

public class ForwardClientX {
    private static boolean handshakeComplete = false;
    protected static Socket clientSocket;
    private enum MessageType {
        ClientHello, ServerHello, Forward, Session
    }

    /**
     * Client application
     * @param args
     * $ java ForwardClient --handshakehost=portfw.kth.se  --handshakeport=2206 \
     *     --targethost=server.kth.se --targetport=6789 \
     *     --usercert=client.pem --cacert=ca.pem --key=client-private.der
     */
    public static void main(String args[]) throws Exception {
        String handshakeHost = args[0];
        int handshakePort = Integer.parseInt(args[1]);
        String targetHost = args[2];
        int targetPort = Integer.parseInt(args[3]);
        X509Certificate userCert = null;
        X509Certificate caCert = null;
        SecretKey clientPvtKey = null;

        System.out.println("Attemping to handshake host " + handshakeHost + " on port " + handshakePort);
        clientSocket = new Socket(handshakeHost, handshakePort);
        clientSocket.setSoTimeout(5000);
        BufferedReader tcpIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        DataOutputStream tcpOut = new DataOutputStream(clientSocket.getOutputStream());

        tcpOut.writeBytes(Base64.getEncoder().encodeToString(ClientHelloMessage.setMsg(userCert).toString().getBytes())); // cert encoding check
        while (true) {
            if (handshakeComplete) break;
            HashMap recvMsg = new HashMap();
            switch (Message.getMsgType(recvMsg)) {
                case ClientHello:
                    System.out.println("Server: Hello Received");
                    X509Certificate xcert = (X509Certificate) recvMsg.get("Certificate");
                    VerifyCertificate.validate(xcert);
                    tcpOut.writeBytes(ServerHelloMessage.setMsg(userCert).toString());
                    break;
                case ServerHello:
                    System.out.println("Client: Hello Received");
                    X509Certificate zcert = (X509Certificate) recvMsg.get("Certificate");
                    VerifyCertificate.validate(zcert);
                    tcpOut.writeBytes(ForwardMessage.setMsg(targetHost, targetPort).toString());
                    break;
                case Forward:
                    System.out.println("Server: Forward Received");
                    SecretKey secretKey = null;
                    byte[] iv = null;
                    String sessionHost = null;
                    int sessionPort = 0;
                    tcpOut.writeBytes(SessionMessage.setMsg(secretKey, iv, sessionHost, sessionPort).toString());
                case Session:
                    System.out.println("Client: Session Received. Handshake Complete");
                    handshakeComplete = true;
            }
        }
        tcpIn.close();
        tcpOut.close();
    }

    private abstract static class Message {
        public static MessageType getMsgType(HashMap<String,String> msg) {
            return MessageType.valueOf(msg.get("MessageType"));
        }
    }

    private abstract static class ClientHelloMessage extends Message {
        public static HashMap<String,String> setMsg(X509Certificate certificate) throws CertificateEncodingException {
            HashMap<String,String> msg = new HashMap<>();
            msg.put("MessageType", "ClientHello");
            msg.put("Certificate", Base64.getEncoder().encodeToString(certificate.getEncoded()));
            return msg;
        }
        public static X509Certificate getCert(HashMap<String,String> msg) throws CertificateException {
            ByteArrayInputStream stream = new ByteArrayInputStream(Base64.getDecoder().decode(msg.get("Certificate")));
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
        }
    }

    private abstract static class ServerHelloMessage extends Message {
        public static HashMap<String, String> setMsg(X509Certificate certificate) throws CertificateEncodingException {
            HashMap<String,String> msg = new HashMap<>();
            msg.put("MessageType", "ServerHello");
            msg.put("Certificate", Base64.getEncoder().encodeToString(certificate.getEncoded()));
            return msg;
        }
        public static X509Certificate getCert(HashMap<String,String> msg) throws CertificateException {
            ByteArrayInputStream stream = new ByteArrayInputStream(Base64.getDecoder().decode(msg.get("Certificate")));
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
        }
    }

    private abstract static class ForwardMessage extends Message {
        public static HashMap<String,String> setMsg(String targetHost, int targetPort) throws CertificateEncodingException {
            HashMap<String,String> msg = new HashMap<>();
            msg.put("MessageType", "Forward");
            msg.put("TargetHost", targetHost);
            msg.put("TargetPort", String.valueOf(targetPort));
            return msg;
        }
        public static String getTargetHost(HashMap<String,String> msg) {
            return msg.get("TargetHost");
        }
        public static int getTargetPort(HashMap<String,String> msg) {
            return Integer.parseInt(msg.get("TargetPort"));
        }
    }

    private abstract static class SessionMessage extends Message {
        public static HashMap<String,String> setMsg(SecretKey sessionKey, byte[] sessionIV, String sessionHost, int sessionPort) throws CertificateEncodingException {
            HashMap<String,String> msg = new HashMap<>();
            msg.put("MessageType", "Session");
            msg.put("SessionKey", Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
            msg.put("SessionIV", Base64.getEncoder().encodeToString(sessionIV));
            msg.put("SessionHost", sessionHost);
            msg.put("SessionPort", String.valueOf(sessionPort));
            return msg;
        }
        public static SecretKey getSessionKey(HashMap<String,String> msg) {
            return new SecretKeySpec(Base64.getDecoder().decode(msg.get("SessionKey")), "AES");
        }
        public static byte[] getSessionIV(HashMap<String,String> msg) {
            return Base64.getDecoder().decode(msg.get("SessionIV"));
        }
        public static String getSessionHost(HashMap<String,String> msg) {
            return msg.get("SessionHost");
        }
        public static int getSessionPort(HashMap<String,String> msg) {
            return Integer.parseInt(msg.get("SessionPort"));
        }
    }
}
