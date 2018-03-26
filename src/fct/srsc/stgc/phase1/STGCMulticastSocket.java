package fct.srsc.stgc.phase1;

import java.io.IOException;
import java.net.DatagramPacket;
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

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");
        super.send(packet);
    }
}
