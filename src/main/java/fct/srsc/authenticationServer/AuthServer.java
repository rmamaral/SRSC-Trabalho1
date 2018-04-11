package fct.srsc.authenticationServer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.NoSuchPaddingException;

import fct.srsc.stgc.phase2.STGCMulticastSocket;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;

public class AuthServer {

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException{

		//hardcoded for now
		String impc = "233.33.33.33";
		STGCMulticastSocket socket = new STGCMulticastSocket(impc, 8989, true, "server");
        System.out.println(InetAddress.getByName(impc));
		socket.joinGroup(InetAddress.getByName(impc));

		DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
		String msg;

		while(true){
			p.setLength(65536); // resize with max size
            AuthenticationRequest ar = socket.receiveASRequest(p);
            System.out.println("Username: " + ar.getUsername());
            System.out.println("Nonce: " + ar.getNonce());
            System.out.println("IPMC: " + ar.getIpmc());
            System.out.println("AuthenticatorSize: " + ar.getAuthenticatorC().length);
            //processRequest(p);
		}
	}

	private static void processRequest (DatagramPacket packet) {
        System.out.println(Base64.getEncoder().encodeToString(Arrays.copyOf(packet.getData(), packet.getLength())));
    }
}
