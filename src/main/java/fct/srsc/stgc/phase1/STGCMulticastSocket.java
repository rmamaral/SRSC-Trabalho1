package fct.srsc.stgc.phase1;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;
import fct.srsc.stgc.phase1.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase1.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase1.utils.Nonce;

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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class STGCMulticastSocket extends MulticastSocket {

    private static final String VERSION = "0";
    private static final String RELEASE = "1";
    private static final String PAYLOAD_TYPE = "M";

    private static final int HEADER_SIZE = 6;
    private static final int MAX_SIZE = 65536;

    private static final byte SEPARATOR = 0x00;

    private ChatRoomConfig config;
    private Cipher c;
    private int id = 1;
    private List<String> nounceList;

    public STGCMulticastSocket(String groupAddress, boolean authenticationServer) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super();
        init(groupAddress, authenticationServer);
    }

    public STGCMulticastSocket(String groupAddress, int port, boolean authenticationServer) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(port);
        init(groupAddress, authenticationServer);
    }

    public STGCMulticastSocket(String groupAddress, SocketAddress bindAdrress, boolean authenticationServer) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(bindAdrress);
        init(groupAddress, authenticationServer);
    }

    private void init(String groupAddress, boolean authenticationServer) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
    	config = ReadFromConfig.readFromConfig(groupAddress);
        
        if(authenticationServer)
        	System.out.println("authServer: " + authenticationServer);
        
        c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());
        nounceList = new ArrayList<String>();
    }
    

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");
        
        Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());

        byte[] payload = encodePayload(key64, packet);//c.doFinal(packet.getData());

        byte[] header = buildHeader(payload.length);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(header);
        outputStream.write(SEPARATOR);
        outputStream.write(payload);

        //Setting encrypted data and length to packet
        packet.setData(outputStream.toByteArray());
        packet.setLength(outputStream.size());

        super.send(packet);
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
        System.out.println("Receiving message through secure channel");

        DatagramPacket p = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

        super.receive(p);

        Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());

        //Header size + 1 because of the delimiter between header/payload (6 bytes of header + 1 delimiter)
        byte[] enc = Arrays.copyOfRange(p.getData(), HEADER_SIZE + 1, p.getLength());

        byte[] message = decodePayload(key64, enc);

        packet.setData(Arrays.copyOfRange(message, 0, MAX_SIZE));
        packet.setLength(message.length);

        packet.setAddress(p.getAddress());
        packet.setPort(p.getPort());
    }

    private Key getKeyFromKeyStore(String type, String keystore, String key, char[] keyPassword, char[] keyStorePassword) {

        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            // Keystore where symmetric keys are stored (type JCEKS)
            FileInputStream stream = new FileInputStream(keystore);
            keyStore.load(stream, keyStorePassword);

            Key key1 = keyStore.getKey(key, keyPassword);

            return key1;
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] buildHeader(int payloadSize) throws IOException {
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

    private byte[] encodePayload(Key key, DatagramPacket packet) throws IOException {

        try {

            //Build mp, id nonce and message
            ByteArrayOutputStream mp = new ByteArrayOutputStream();

            String dateTimeString = Long.toString(new Date().getTime());
            byte[] nonceByte = generateNounce();
            byte[] painText = Arrays.copyOf(packet.getData(), packet.getLength());

            mp.write(Integer.toString(id).getBytes());
            mp.write(SEPARATOR);
            mp.write(nonceByte);
            mp.write(SEPARATOR);
            mp.write(painText);

            //Create hash of mp
            Mac hMac = Mac.getInstance(config.getMacKm(), config.getProvider());
            Key hMacKey = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macInKey", "password".toCharArray(), "password".toCharArray());

            hMac.init(hMacKey);
            hMac.update(mp.toByteArray());

            //Add mp hash
            mp.write(hMac.doFinal());

            //Cipher mp + hash
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] ecryptedCore = c.doFinal(mp.toByteArray());

            //Create hash for core
            Mac hMacOut = Mac.getInstance(config.getMacKa(), config.getProvider());
            Key hMacKeyOut = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macOutKey", "password".toCharArray(), "password".toCharArray());

            hMacOut.init(hMacKeyOut);
            hMacOut.update(ecryptedCore);

            //Build final
            ByteArrayOutputStream full = new ByteArrayOutputStream();
            full.write(ecryptedCore);
            full.write(hMacOut.doFinal());

            return full.toByteArray();
        } catch (Exception e) {
            System.out.println(e);
        }

        return null;
    }

    private byte[] decodePayload(Key key, byte[] packet) throws IOException {

        try {
            int packetLength = packet.length;

            Mac hMacOut = Mac.getInstance(config.getMacKa(), config.getProvider());
            Key hMacKey = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macOutKey", "password".toCharArray(), "password".toCharArray());


            byte[] hMacString = new byte[hMacOut.getMacLength()];
            System.arraycopy(packet, packetLength - hMacOut.getMacLength(), hMacString, 0, hMacOut.getMacLength());

            hMacOut.init(hMacKey);
            hMacOut.update(packet, 0, (packet.length - hMacOut.getMacLength()));

            if (!MessageDigest.isEqual(hMacOut.doFinal(), hMacString))
                throw new MessageIntegrityBrokenException();

            c.init(Cipher.DECRYPT_MODE, key);

            byte[] content = c.doFinal(packet, 0, (packet.length - hMacOut.getMacLength()));


            Mac hMacIn = Mac.getInstance(config.getMacKm(), config.getProvider());
            Key hMacInKey = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macInKey", "password".toCharArray(), "password".toCharArray());

            byte[] hMacInString = new byte[hMacIn.getMacLength()];

            System.arraycopy(content, content.length - hMacIn.getMacLength(), hMacInString, 0, hMacIn.getMacLength());


            hMacIn.init(hMacInKey);
            hMacIn.update(content, 0, (content.length - hMacIn.getMacLength()));

            if (!MessageDigest.isEqual(hMacIn.doFinal(), hMacInString))
                throw new MessageIntegrityBrokenException();


            byte[] messageBytes = Arrays.copyOfRange(content, 0, content.length - hMacIn.getMacLength());

            int nounceIndex = -1;
            String nounce = null;
            byte[] actualMessage = new byte[MAX_SIZE];

            int counter = 0;
            for (int i = 0; i < messageBytes.length; i++) {
                if (messageBytes[i] == SEPARATOR) {
                    counter++;
                }
                if (counter == 1 && nounceIndex == -1){
                    nounceIndex = i;
                }

                if (counter == 2) {
                    nounce = new String(Arrays.copyOfRange(messageBytes, nounceIndex+1, i));
                    actualMessage = Arrays.copyOfRange(messageBytes, i + 1, messageBytes.length);
                    break;
                }
            }

            if (!nounceList.contains(nounce))
                nounceList.add(nounce);
            else {
                throw new DuplicatedNonceException();
            }

            return actualMessage;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] generateNounce() {
        return Nonce.randomString().getBytes();
    }
}
