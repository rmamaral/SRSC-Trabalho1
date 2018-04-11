package fct.srsc.authenticationServer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;

import fct.srsc.stgc.phase2.STGCMulticastSocket;

public class AuthServer {

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException{

		String impc = args[0];
		MulticastSocket socket = new STGCMulticastSocket(impc, 8989, true, "server");
		socket.joinGroup(socket.getInetAddress());

		DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
		String msg;

		while(true){
			p.setLength(65536); // resize with max size
			socket.receive(p);
		}
	}
}
