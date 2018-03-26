package fct.srsc.stgc.phase1;

import java.io.IOException;
import java.net.MulticastSocket;
import java.net.SocketAddress;

public class STGCMulticastSocket extends MulticastSocket {

    public STGCMulticastSocket() throws IOException {
        super();
    }

    public STGCMulticastSocket(int port) throws IOException {
        super(port);
    }

    public STGCMulticastSocket(SocketAddress bindAdrress) throws IOException {
        super(bindAdrress);
    }
}
