package fct.srsc.stgc.phase2;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;
import fct.srsc.stgc.phase1.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase1.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase2.exceptions.UserNotRegisteredException;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.utils.Nonce;
import org.bouncycastle.util.encoders.Hex;

@SuppressWarnings("Duplicates")
public class STGCMulticastSocket extends MulticastSocket {

    private static final String VERSION = "0";
    private static final String RELEASE = "1";

    private static final char STGC_TLS = 'M';
    private static final char STGC_SAP = 'S';

    //for accessing stgcsap.auth
    private static final String AUTH_CIPHERSUITE = "STGC-SAP";
    private static final String AUTH_PROVIDER = "PROVIDER";
    private static final String AS_LOCATION = "233.33.33.33";
    private static final int AS_LOCATION_PORT = 8989;

    //For encryption and decryption of PBE data
    private static final byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
    private static final int iterationCount = 2048;
    //

    private static final int HEADER_SIZE = 6;
    private static final int MAX_SIZE = 65536;

    private static final byte SEPARATOR = 0x00;

    private Cipher c;
    private int id = 1;
    private List<String> nounceList;

    private String groupAddress;
    private String username;
    private boolean authenticationServer;

    public STGCMulticastSocket(String groupAddress, boolean authenticationServer, String username) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super();
        init(groupAddress, authenticationServer, username);
    }

    public STGCMulticastSocket(String groupAddress, int port, boolean authenticationServer, String username) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super(port);
        init(groupAddress, authenticationServer, username);
    }

    public STGCMulticastSocket(String groupAddress, SocketAddress bindAdrress, boolean authenticationServer, String username) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super(bindAdrress);
        init(groupAddress, authenticationServer, username);
    }

    private void init(String groupAddress, boolean authenticationServer, String username) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException {
        nounceList = new ArrayList<String>();
        this.authenticationServer = authenticationServer;

        //config = ReadFromConfig.readFromConfig(groupAddress);
        if (authenticationServer) {
            System.out.println("authServer: " + authenticationServer);
        } else {

            /**String nonce =*/ establishSecureConnection(groupAddress, username);

            //receiveReplyFromAS ();

            //c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());

        }
    }


    private void establishSecureConnection(String groupAddress, String username) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        this.username = username;
        this.groupAddress = groupAddress;

        connectAuthenticationServer();

        //TODO: wait for answer of authentication server and process that reply
    }


    @Override
    public void send(DatagramPacket packet) throws IOException {
		/*System.out.println("Sending message through secure channel");

		Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());

		byte[] payload = encodePayload(key64, packet);//c.doFinal(packet.getData());

		byte[] header = buildHeader(payload.length, STGC_TLS);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(header);
		outputStream.write(SEPARATOR);
		outputStream.write(payload);

		//Setting encrypted data and length to packet
		packet.setData(outputStream.toByteArray());
		packet.setLength(outputStream.size());*/

        super.send(packet);
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {
		/*System.out.println("Receiving message through secure channel");

		DatagramPacket p = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);*/

        super.receive(packet);

		/*Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());

		//Header size + 1 because of the delimiter between header/payload (6 bytes of header + 1 delimiter)
		byte[] enc = Arrays.copyOfRange(p.getData(), HEADER_SIZE + 1, p.getLength());

		byte[] message = decodePayload(key64, enc);

		packet.setData(Arrays.copyOfRange(message, 0, MAX_SIZE));
		packet.setLength(message.length);

		packet.setAddress(p.getAddress());
		packet.setPort(p.getPort());*/
    }

    public void receiveFromClient(DatagramPacket packet) throws IOException {
		/*DatagramPacket p = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

		super.receive(p);
		
		//Key key64 = ?????

		//Header size + 1 because of the delimiter between header/payload (6 bytes of header + 1 delimiter)
		byte[] enc = Arrays.copyOfRange(p.getData(), HEADER_SIZE + 1, p.getLength());

		byte[] message = decodePayloadFromClient(key64, enc);*/

    }

    public void connectAuthenticationServer() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("Establishing Secure Connection");

        //TODO: For now hardcoded -> ask professor how it is passed
        MessageDigest md = MessageDigest.getInstance("SHA-512", "BC");
        byte[] hashedPassword = Hex.decode(readKeyFromConfig(username));


        DatagramPacket packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

        //TODO delete this initialization
        byte[] payload = new byte[1];
        if (!authenticationServer) {
            payload = encodePayloadToAS(hashedPassword, packet);//c.doFinal(packet.getData());
        } else {
            //payload = encodePayloadToClient(hashedPassword);//c.doFinal(packet.getData());
        }

        byte[] header = buildHeader(payload.length, STGC_SAP);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(header);
        outputStream.write(SEPARATOR);
        outputStream.write(payload);

        //Setting encrypted data and length to packet
        packet.setData(outputStream.toByteArray());
        packet.setLength(outputStream.size());

        packet.setAddress(InetAddress.getByName(AS_LOCATION));
        packet.setPort(AS_LOCATION_PORT);

        System.out.println(Base64.getEncoder().encodeToString(packet.getData()));
        super.send(packet);
    }

    public AuthenticationRequest receiveASRequest(DatagramPacket packet) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        super.receive(packet);

        byte[] dataParts = Arrays.copyOfRange(packet.getData(), HEADER_SIZE + 1, packet.getLength());
        //TODO: Process Header --> Arrays.copyOf(packet.getData(), HEADER_SIZE);

        AuthenticationRequest ar = buildASRequest(dataParts);
        verifySignature (ar);


        return ar;
    }

    private void verifySignature (AuthenticationRequest ar) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String userHasahedPassword = readKeyFromConfig(ar.getUsername());
        if(userHasahedPassword == null){
            throw new UserNotRegisteredException();
        }

        //get ciphersuite from config file [0] -> payload ciphersuite | [1] -> hMAC ciphersuite
        String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
        String provider = readFromStgcSapAuth(AUTH_PROVIDER);

        c = Cipher.getInstance(ciphersuite[0], provider);
        PBEKeySpec pbeSpec = new PBEKeySpec(userHasahedPassword.toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
        Key sKey = keyFact.generateSecret(pbeSpec);

        c.init(c.DECRYPT_MODE, sKey);

        byte [] data = c.doFinal(ar.getAuthenticatorC());

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

    private byte[] buildHeader(int payloadSize, char type) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        outputStream.write(VERSION.getBytes());
        outputStream.write(RELEASE.getBytes());

        outputStream.write(0);
        outputStream.write(type);

        outputStream.write(0);

        outputStream.write((short) payloadSize);

        assert outputStream.toByteArray().length == HEADER_SIZE;

        return outputStream.toByteArray();
    }

    /*private byte[] encodePayload(Key key, DatagramPacket packet) throws IOException {

        try {

            //Build mp, id nonce and message
            ByteArrayOutputStream mp = new ByteArrayOutputStream();

            String dateTimeString = Long.toString(new Date().getTime());
            byte[] nonceByte = generateNounce(STGC_TLS);
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
    }*/

    private byte[] encodePayloadToAS(byte[] hashedPassword, DatagramPacket packet) throws IOException {

        try {
            //get ciphersuite from config file [0] -> payload ciphersuite | [1] -> hMAC ciphersuite
            String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
            String provider = readFromStgcSapAuth(AUTH_PROVIDER);

            c = Cipher.getInstance(ciphersuite[0], provider);

            PBEKeySpec pbeSpec = new PBEKeySpec(Hex.toHexString(hashedPassword).toCharArray(), salt, iterationCount);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
            Key sKey = keyFact.generateSecret(pbeSpec);

            c.init(c.ENCRYPT_MODE, sKey);

            //Build nounce, ipmc, sha-512(pwd) and MACk(X)
            ByteArrayOutputStream authC = new ByteArrayOutputStream();

            byte[] nonce = generateNounce(STGC_SAP);

            authC.write(nonce);
            authC.write(SEPARATOR);
            authC.write(this.groupAddress.getBytes());
            authC.write(SEPARATOR);
            authC.write(hashedPassword);
            authC.write(SEPARATOR);


            ByteArrayOutputStream authC_NoIPMC = new ByteArrayOutputStream();
            authC_NoIPMC.write(nonce);
            authC_NoIPMC.write(SEPARATOR);
            authC_NoIPMC.write(hashedPassword);
            authC_NoIPMC.write(SEPARATOR);

            //Create mac of authC
            MessageDigest messageDigest = MessageDigest.getInstance("md5", "BC");

            byte[] hMd5 = messageDigest.digest(authC_NoIPMC.toByteArray());
            Mac hMac = Mac.getInstance(ciphersuite[1], provider);
            SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);

            hMac.init(keySpec);
            hMac.update(authC.toByteArray());

            //Add mp hash
            authC.write(hMac.doFinal());

            //Cipher mp + hash
            c.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] ecryptedCore = c.doFinal(authC.toByteArray());

            //Build Final -> clientId, NounceC, IPMC, AuthC
            ByteArrayOutputStream full = new ByteArrayOutputStream();
            full.write(this.username.getBytes());
            full.write(SEPARATOR);
            full.write(nonce);
            full.write(SEPARATOR);
            full.write(this.groupAddress.getBytes());
            full.write(SEPARATOR);
            full.write(ecryptedCore);

            System.out.println(Base64.getEncoder().encodeToString(ecryptedCore));
            return full.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] encodePayloadToClient(String password, DatagramPacket packet) throws IOException {


        return null;

    }

    /*private byte[] decodePayload(Key key, byte[] packet) throws IOException {

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
                if (counter == 1 && nounceIndex == -1) {
                    nounceIndex = i;
                }
                if (counter == 2) {
                    nounce = new String(Arrays.copyOfRange(messageBytes, nounceIndex + 1, i));
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
    }*/

    /*private byte[] decodePayloadFromClient(Key key, byte[] packet) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int packetLength = packet.length;

        c.init(Cipher.DECRYPT_MODE, key);

        byte[] authenticatorC;
        int counter = 0;
        boolean found = false;
        int aux = 0;
        for (int i = 0; i < packet.length; i++) {
            if (packet[i] == SEPARATOR) {
                counter++;
                if (counter == 3) {
                    aux = i + 1;
                    found = true;
                }
            }
        }
        if (!found) {
            authenticatorC = null;
        } else {
            authenticatorC = Arrays.copyOfRange(packet, aux, packet.length);
        }
        byte[] content = c.doFinal(packet, packet.length - authenticatorC.length, packet.length);


        Mac hMac = Mac.getInstance(config.getMacKm(), config.getProvider());
        Key hMacKey = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macOutKey", "password".toCharArray(), "password".toCharArray());

        byte[] hMacString = new byte[hMac.getMacLength()];

        System.arraycopy(packet, packetLength - hMac.getMacLength(), hMacString, 0, hMac.getMacLength());

        hMac.init(hMacKey);
        hMac.update(packet, 0, (packet.length - hMac.getMacLength()));

        if (!MessageDigest.isEqual(hMac.doFinal(), hMacString))
            throw new MessageIntegrityBrokenException();


        return packet;


    }*/

    private AuthenticationRequest buildASRequest(byte[] data) {
        int lastIndex = 0;
        int counter = 0;
        AuthenticationRequest ar = new AuthenticationRequest();

        for (int i = 0; i < data.length; i++) {
            if (data[i] == SEPARATOR) {
                if (counter < 3) {
                    if (counter == 0) {
                        ar.setUsername(new String(Arrays.copyOfRange(data, lastIndex, i)));
                        lastIndex = i + 1;
                        counter++;
                    } else {
                        if (counter == 1) {
                            ar.setNonce(new String(Arrays.copyOfRange(data, lastIndex, i)));
                            lastIndex = i + 1;
                            counter++;
                        } else {
                            if (counter == 2) {
                                ar.setIpmc(new String(Arrays.copyOfRange(data, lastIndex, i)));
                                lastIndex = i + 1;
                                ar.setAuthenticatorC(Arrays.copyOfRange(data, lastIndex, data.length));
                                break;
                            }
                        }
                    }
                }
            }
        }
        return ar;
    }

    private String readFromStgcSapAuth(String property) {
        try {
            Properties prop = new Properties();
            InputStream input = this.getClass().getResourceAsStream("/phase2/as/stgcsap.auth");

            // load a properties file
            prop.load(input);
            return prop.getProperty(property);

        } catch (IOException io) {
            io.printStackTrace();
            return null;
        }
    }

    private String readKeyFromConfig (String username) {
        try {
            Properties prop = new Properties();
            InputStream input = this.getClass().getResourceAsStream("/phase2/as/users.conf");

            // load a properties file
            prop.load(input);
            return prop.getProperty(username);

        } catch (IOException io) {
            io.printStackTrace();
            return null;
        }
    }

    private byte[] generateNounce(char type) {
        return Nonce.randomNonce(type).getBytes();
    }
}
