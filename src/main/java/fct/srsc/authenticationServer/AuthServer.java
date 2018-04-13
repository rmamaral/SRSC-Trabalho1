package fct.srsc.authenticationServer;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import fct.srsc.stgc.phase2.STGCMulticastSocket;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;

public class AuthServer {

	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {

		AuthenticationData authData = new AuthenticationData();

		//hardcoded for now
		String impc = "233.33.33.33";
		STGCMulticastSocket socket = new STGCMulticastSocket(impc, 8989, true, "server");
		System.out.println(InetAddress.getByName(impc));
		socket.joinGroup(InetAddress.getByName(impc));

		DatagramPacket p = new DatagramPacket(new byte[65536], 65536);

		while (true) {

			p.setLength(65536); // resize with max size
			AuthenticationRequest ar = socket.receiveClientRequest(p);

			try {
				byte[] data = authData.decryptMessage(ar);

				authData.verifySignature(ar, data);

				byte[] payload = authData.encrypt(ar);

				socket.sendToClient(payload, ar.getClientAddress(), ar.getClientPort());

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}