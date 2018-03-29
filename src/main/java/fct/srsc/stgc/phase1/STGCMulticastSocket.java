package fct.srsc.stgc.phase1;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

public class STGCMulticastSocket extends MulticastSocket {

    private ChatRoomConfig config;
    private Cipher c;

    public STGCMulticastSocket(String groupAddress) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super();
        config = ReadFromConfig.readFromConfig(groupAddress);
        c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());
    }

    public STGCMulticastSocket(String groupAddress, int port) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(port);
        config = ReadFromConfig.readFromConfig(groupAddress);
        c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());
    }

    public STGCMulticastSocket(String groupAddress, SocketAddress bindAdrress) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(bindAdrress);
        config = ReadFromConfig.readFromConfig(groupAddress);
        c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());
    }
    
    public Key getKeyFromKeyStore(String type, String keystore, String key, char[] keyPassword, char[] keyStorePassword) {

    	try {
    	KeyStore keyStore = KeyStore.getInstance(type);
        	   // Keystore where symmetric keys are stored (type JCEKS)
   	    FileInputStream stream = new FileInputStream(keystore);
               // Password of the keystore: in ths case is "password"
   	    keyStore.load(stream, keyStorePassword);

               // We decided to store the keys in these entries: mykey1, mykey2
               // Also, we used "password" to protect each entry...
               // See how the keytool was used ...

   	    Key key1 = keyStore.getKey(key, keyPassword);
   	    System.out.println(Base64.getEncoder().encodeToString(key1.getEncoded()));
   	    return key1;
   	    
    	}
    	catch(Exception e) {
    		return null;
    	}
    	
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");

        try {
        	
        	Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());
        
            c.init(Cipher.ENCRYPT_MODE, key64);
            byte[] enc = c.doFinal(packet.getData());

            //Setting encrypted data and length to packet
            packet.setData(enc);
            packet.setLength(enc.length);

            super.send(packet);
        } catch (Exception e) {
            System.out.println("Message not sent. An error occured");
            e.printStackTrace();
        }
    }

    @Override
    public void receive(DatagramPacket packet) {
        System.out.println("Receiving message through secure channel");

        try {
            DatagramPacket p = new DatagramPacket(new byte[65356], 65356);

            super.receive(p);
            Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());
            c.init(Cipher.DECRYPT_MODE, key64);
            byte[] enc = c.doFinal(Arrays.copyOf(p.getData(), p.getLength()));

            packet.setLength(enc.length);
            packet.setData(enc);

        } catch (Exception e) {
            System.out.println("Message not received/decrypted. An error occured");
            e.printStackTrace();
        }
    }
}
