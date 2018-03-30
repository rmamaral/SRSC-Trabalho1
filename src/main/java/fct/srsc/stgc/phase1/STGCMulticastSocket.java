package fct.srsc.stgc.phase1;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class STGCMulticastSocket extends MulticastSocket {

    private static final String VERSION = "0";
    private static final String RELEASE = "1";
    private static final String PAYLOAD_TYPE = "M";

    private static final int HEADER_SIZE = 6;

    private ChatRoomConfig config;
    private Cipher c;
    private int id = 0;

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

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");

        try {
        	Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());
        	    
            byte[] payload = buildPayload(key64, packet);//c.doFinal(packet.getData());

            byte[] header = buildHeader(payload.length);
            System.out.println("header size: " + header.length);
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(header);
            outputStream.write(0);
            outputStream.write(payload);
            
            //Setting encrypted data and length to packet
            packet.setData(outputStream.toByteArray());
            packet.setLength(outputStream.size());

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
            DatagramPacket p = new DatagramPacket(new byte[65536], 65536);

            super.receive(p);
            Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());
            c.init(Cipher.DECRYPT_MODE, key64);

            //Header size + 1 because of the delimiter between header/payload (6 bytes of header + 1 delimiter)
            byte[] enc = c.doFinal(Arrays.copyOfRange(p.getData(), HEADER_SIZE + 1, p.getLength()));

            packet.setLength(enc.length);
            packet.setData(enc);

        } catch (Exception e) {
            System.out.println("Message not received/decrypted. An error occured");
            e.printStackTrace();
        }
    }

    private Key getKeyFromKeyStore(String type, String keystore, String key, char[] keyPassword, char[] keyStorePassword) {

        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            // Keystore where symmetric keys are stored (type JCEKS)
            FileInputStream stream = new FileInputStream(keystore);
            keyStore.load(stream, keyStorePassword);

            Key key1 = keyStore.getKey(key, keyPassword);
            System.out.println(Base64.getEncoder().encodeToString(key1.getEncoded()));

            return key1;
        }
        catch(Exception e) {
            return null;
        }
    }

    private byte [] buildHeader (int payloadSize) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        outputStream.write(VERSION.getBytes());
        outputStream.write(RELEASE.getBytes());

        outputStream.write(0);
        outputStream.write(PAYLOAD_TYPE.getBytes());

        outputStream.write(0);
        outputStream.write((short) payloadSize);

        assert outputStream.toByteArray().length == HEADER_SIZE;

        return outputStream.toByteArray();
    }
    
   private byte [] buildPayload (Key key, DatagramPacket packet) throws IOException {
        
    try {
    	  //needed?  
        Cipher c2 = c; 
    	
        //Build mp, id nonce and message
    	ByteArrayOutputStream mp = new ByteArrayOutputStream();
        
        String dateTimeString = Long.toString(new Date().getTime());
        byte[] nonceByte = dateTimeString.getBytes();
        byte[] painText = packet.getData();
        
        mp.write(id);
        mp.write(nonceByte);
        mp.write(painText);
        
        //Cipher mp
        c.init(Cipher.ENCRYPT_MODE, key);        
        byte[] ecryptedMp = c.doFinal(mp.toByteArray());
        
        //Create hash of mp
        Mac hMac = Mac.getInstance("HMacSHA1", "BC");
        Key hMacKey = new SecretKeySpec(key.getEncoded(), "HMacSHA1");
        
        hMac.init(hMacKey);
        hMac.update(mp.toByteArray()); 
        
        //Build mp with his hash
        ByteArrayOutputStream mpMac = new ByteArrayOutputStream();
        mpMac.write(ecryptedMp);
        mpMac.write(hMac.doFinal());
        
        //Build core
        ByteArrayOutputStream core = new ByteArrayOutputStream();
        core.write(key.toString().getBytes());
        core.write(mpMac.toByteArray());
        
        //Cipher core
        c2.init(Cipher.ENCRYPT_MODE, key);
        byte[] ecryptedCore = c2.doFinal(core.toByteArray());
        
        //Create hash for core
        Mac hMacOut = Mac.getInstance("HMacSHA1", "BC");
        Key hMacKeyOut = new SecretKeySpec(key.getEncoded(), "HMacSHA1");
        
        hMacOut.init(hMacKeyOut);
        hMacOut.update(ecryptedCore); 
        
        //Build final 
        ByteArrayOutputStream full = new ByteArrayOutputStream(); 
        full.write(ecryptedCore);
        full.write(hMacOut.doFinal());
        
        System.out.println("cipher text -> " +Base64.getEncoder().encodeToString(full.toByteArray()));
        
        return full.toByteArray();
    }
    catch(Exception e) {
    	System.out.println(e);
    }
    	
       return null;
    }
}
