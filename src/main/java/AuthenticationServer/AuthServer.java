package AuthenticationServer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;

import fct.srsc.stgc.phase1.STGCMulticastSocket;

public class AuthServer {
	
	public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException{
		
		String impc = args[0];
		
		MulticastSocket socket = new STGCMulticastSocket(impc, 8989, true);
		
		socket.joinGroup(socket.getInetAddress());

        DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
        String msg;

        while(true){
        	
        }
		
        
		
	}
}
