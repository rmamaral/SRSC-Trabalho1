package fct.srsc.stgc.phase1;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class STGCMulticastSocket extends MulticastSocket {

    private final SecretKey key64 = new SecretKeySpec(new byte[] {
            0x00, 0x01,0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }, "blowfish");

    Cipher c;

    public STGCMulticastSocket() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super();
        c = Cipher.getInstance("blowfish/ECB/PKCS5Padding", "BC");
    }

    public STGCMulticastSocket(int port) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(port);
        c = Cipher.getInstance("blowfish/ECB/PKCS5Padding", "BC");
    }

    public STGCMulticastSocket(SocketAddress bindAdrress) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(bindAdrress);
        c = Cipher.getInstance("blowfish/ECB/PKCS5Padding", "BC");
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");

        try {
            c.init(Cipher.ENCRYPT_MODE, key64);
            byte[] enc = c.doFinal(packet.getData());
            packet.setData(enc);

            super.send(packet);
        } catch (Exception e) {
            System.out.println("Message not sent. An error occured");
            e.printStackTrace();
        }
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        System.out.println("Receiving message through secure channel");

        try {
            super.receive(packet);

            c.init(Cipher.DECRYPT_MODE, key64);
            byte[] enc = c.doFinal(packet.getData());
            packet.setData(enc);

        } catch (Exception e) {
            System.out.println("Message not received/decrypted. An error occured");
            e.printStackTrace();
        }
    }
}
