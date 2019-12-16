public class ForwardServerX extends Thread implements Runnable {
    /**
     * Server application
     * @param args
     * $ java ForwardServer --handshakeport=2206 --usercert=server.pem
     *      --cacert=ca.pem --key=server-private.der
     */
    public static void main(String args[]) {
        String handshakeport, usercert, cacert, pvtkey;
        handshakeport=args[0]; usercert=args[1]; cacert=args[2]; pvtkey=args[3];
    }
}

