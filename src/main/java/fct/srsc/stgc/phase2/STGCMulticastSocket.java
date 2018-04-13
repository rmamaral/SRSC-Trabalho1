package fct.srsc.stgc.phase2;

import fct.srsc.stgc.phase2.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase2.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase2.exceptions.SecureConnectionFailedException;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.phase2.model.TicketAS;
import fct.srsc.stgc.utils.Nonce;
import fct.srsc.stgc.utils.ReadFromConfigs;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@SuppressWarnings("Duplicates")
public class STGCMulticastSocket extends MulticastSocket {

    private static final String VERSION = "0";
    private static final String RELEASE = "1";

    private static final char STGC_TLS = 'M';
    private static final char STGC_SAP = 'S';

    private static final String PROVIDER_BEFORE_TICKET = "BC";
    private static final String DEFAULT_SHA = "SHA-512";
    private static final String DEFAULT_MD5 = "md5";

    //for accessing stgcsap.auth
    private static final String AUTH_CIPHERSUITE = "STGC-SAP";
    private static final String AUTH_PROVIDER = "PROVIDER";

    //Authentication Server Location
    private static final String AS_LOCATION = "233.33.33.33";
    private static final int AS_LOCATION_PORT = 8989;

    private static final String ERROR = "ERROR";

    //For encryption and decryption of PBE data
    private static final byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
    private static final int iterationCount = 2048;
    //

    private static final int HEADER_SIZE = 6;
    private static final int MAX_SIZE = 65536;

    private static final byte SEPARATOR = 0x00;

    private TicketAS ticket;
    private Cipher c;
    private int id = 1;
    private List<String> nounceList;

    private String groupAddress;
    private String username;
    private boolean authenticationServer;

    public STGCMulticastSocket(String groupAddress, boolean authenticationServer, String username, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super();
        init(groupAddress, authenticationServer, username, password);
    }

    public STGCMulticastSocket(String groupAddress, int port, boolean authenticationServer, String username, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super(port);
        init(groupAddress, authenticationServer, username, password);
    }

    public STGCMulticastSocket(String groupAddress, SocketAddress bindAdrress, boolean authenticationServer, String username, String password) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        super(bindAdrress);
        init(groupAddress, authenticationServer, username, password);
    }

    private void init(String groupAddress, boolean authenticationServer, String username, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException {
        nounceList = new ArrayList<String>();
        this.authenticationServer = authenticationServer;

        if (authenticationServer) {
            System.out.println("authServer: " + authenticationServer);
        } else {

            super.joinGroup(InetAddress.getByName(groupAddress));
            //Encode PW given by input
            MessageDigest md = MessageDigest.getInstance(DEFAULT_SHA, PROVIDER_BEFORE_TICKET);
            byte[] pwBytes = md.digest(password.getBytes());

            try {
                establishSecureConnection(groupAddress, username, Hex.toHexString(pwBytes));
                c = Cipher.getInstance(new String(ticket.getCiphersuite()), new String(ticket.getProvider()));

                //Leaving the group so the client can join again...
                super.leaveGroup(InetAddress.getByName(groupAddress));

            } catch (Exception e) {
                throw new SecureConnectionFailedException("Could not establish a secure connection");
            }
        }
    }


    private void establishSecureConnection(String groupAddress, String username, String passwordHex) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        this.username = username;
        this.groupAddress = groupAddress;

        //TODO: For now hardcoded -> ask professor how it is passed
        MessageDigest md = MessageDigest.getInstance(DEFAULT_SHA, PROVIDER_BEFORE_TICKET);
        byte[] hashedPassword = Hex.decode(passwordHex);

        byte[] nounce = connectAuthenticationServer(hashedPassword);

        DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
        p.setLength(65536);
        System.out.println("Waiting for AuthServer response....");
        super.setSoTimeout(5000);
        super.receive(p);

        if (new String(Arrays.copyOf(p.getData(), p.getLength())).equals(ERROR)){
            throw new SecureConnectionFailedException();
        }

        System.out.println("Received response from AuthServer");
        ticket = decodePayloadFromAS(Arrays.copyOf(p.getData(), p.getLength()), nounce, hashedPassword);
        System.out.println("Secure Connection Established");

        System.out.println("cipher: " + new String(ticket.getCiphersuite()));
        System.out.println("kMAlg: " + new String(ticket.getKmAlgorithm()));
        System.out.println("kAAlg: " + new String(ticket.getKaAlgorithm()));
        System.out.println("Exp: " + ticket.getExpire());
        System.out.println("Provider: " + new String(ticket.getProvider()));
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        System.out.println("Sending message through secure channel");

        Key key64 = new SecretKeySpec(ticket.getKs(), new String(ticket.getCiphersuite()));
        byte[] payload = encodePayload(key64, packet);

        byte[] header = buildHeader(payload.length, STGC_TLS);

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

        Key key64 = new SecretKeySpec(ticket.getKs(), new String(ticket.getCiphersuite()));

        //Header size + 1 because of the delimiter between header/payload (6 bytes of header + 1 delimiter)
        byte[] enc = Arrays.copyOfRange(p.getData(), HEADER_SIZE + 1, p.getLength());

        byte[] message = decodePayload(key64, enc);

        packet.setData(Arrays.copyOfRange(message, 0, MAX_SIZE));
        packet.setLength(message.length);

        packet.setAddress(p.getAddress());
        packet.setPort(p.getPort());
    }


    public byte[] connectAuthenticationServer(byte[] hashedPassword) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("Establishing Secure Connection");

        DatagramPacket packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

        //TODO delete this initialization
        byte[] payload;
        List<byte[]> payloadWithNounce = new ArrayList<byte[]>(2);
        if (!authenticationServer) {
            payloadWithNounce = encodePayloadToAS(hashedPassword, packet);//c.doFinal(packet.getData());
            payload = payloadWithNounce.get(0);

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

            super.send(packet);
            System.out.println("Request to AuthServer sent");

            return payloadWithNounce.get(1);
        } else {
            return null;
        }
    }

    public void sendToClient(byte[] p, InetAddress clientAddress, int port) {
        try {

            DatagramPacket packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);
            packet.setLength(p.length);
            packet.setData(p);

            packet.setAddress(clientAddress);
            packet.setPort(port);

            super.send(packet);
            System.out.println("sended from server to client");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public AuthenticationRequest receiveClientRequest(DatagramPacket packet) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        super.receive(packet);
        System.out.println("Client request received from: " + packet.getAddress().toString() + ":" + packet.getPort());
        byte[] dataParts = Arrays.copyOfRange(packet.getData(), HEADER_SIZE + 1, packet.getLength());
        //TODO: Process Header --> Arrays.copyOf(packet.getData(), HEADER_SIZE);

        AuthenticationRequest ar = new AuthenticationRequest(dataParts, packet.getAddress(), packet.getPort());

        return ar;
    }


    private byte[] buildHeader(int payloadSize, char type) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        outputStream.write(VERSION.getBytes());
        outputStream.write(RELEASE.getBytes());

        outputStream.write(SEPARATOR);
        outputStream.write(type);

        outputStream.write(SEPARATOR);

        outputStream.write((short) payloadSize);

        assert outputStream.toByteArray().length == HEADER_SIZE;

        return outputStream.toByteArray();
    }

    private byte[] encodePayload(Key key, DatagramPacket packet) throws IOException {

        try {

            //Build mp, id nonce and message
            ByteArrayOutputStream mp = new ByteArrayOutputStream();

            byte[] nonceByte = Nonce.randomNonce(STGC_TLS).getBytes();
            byte[] painText = Arrays.copyOf(packet.getData(), packet.getLength());

            mp.write(Integer.toString(id).getBytes());
            mp.write(SEPARATOR);
            mp.write(nonceByte);
            mp.write(SEPARATOR);
            mp.write(painText);

            //Create hash of mp
            Mac hMac = Mac.getInstance(new String(ticket.getKmAlgorithm()), new String(ticket.getProvider()));
            Key hMacKey = new SecretKeySpec(ticket.getKm(), new String(ticket.getKmAlgorithm()));

            hMac.init(hMacKey);
            hMac.update(mp.toByteArray());

            //Add mp hash
            mp.write(hMac.doFinal());

            //Cipher mp + hash
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] ecryptedCore = c.doFinal(mp.toByteArray());

            //Create hash for core
            Mac hMacOut = Mac.getInstance(new String(ticket.getKaAlgorithm()), new String(ticket.getProvider()));
            Key hMacKeyOut = new SecretKeySpec(ticket.getKa(), new String(ticket.getKaAlgorithm()));

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

            //Create hash for core
            Mac hMacOut = Mac.getInstance(new String(ticket.getKaAlgorithm()), new String(ticket.getProvider()));
            Key hMacKeyOut = new SecretKeySpec(ticket.getKa(), new String(ticket.getKaAlgorithm()));

            byte[] hMacString = Arrays.copyOfRange(packet, packetLength - hMacOut.getMacLength(), packetLength);

            hMacOut.init(hMacKeyOut);
            hMacOut.update(packet, 0, (packet.length - hMacOut.getMacLength()));

            if (!MessageDigest.isEqual(hMacOut.doFinal(), hMacString))
                throw new MessageIntegrityBrokenException();

            c.init(Cipher.DECRYPT_MODE, key);

            byte[] content = c.doFinal(packet, 0, (packet.length - hMacOut.getMacLength()));

            //Create hash of mp
            Mac hMacIn = Mac.getInstance(new String(ticket.getKmAlgorithm()), new String(ticket.getProvider()));
            Key hMacInKey = new SecretKeySpec(ticket.getKm(), new String(ticket.getKmAlgorithm()));

            byte[] hMacInString = Arrays.copyOfRange(content, content.length - hMacIn.getMacLength(), content.length);

            hMacIn.init(hMacInKey);
            hMacIn.update(content, 0, (content.length - hMacIn.getMacLength()));

            if (!MessageDigest.isEqual(hMacIn.doFinal(), hMacInString))
                throw new MessageIntegrityBrokenException();


            byte[] messageBytes = Arrays.copyOf(content, content.length - hMacIn.getMacLength());

            int nonceIndex = -1;
            String nonce = null;
            byte[] actualMessage = new byte[MAX_SIZE];

            int counter = 0;
            for (int i = 0; i < messageBytes.length; i++) {
                if (messageBytes[i] == SEPARATOR) {
                    counter++;
                }
                if (counter == 1 && nonceIndex == -1) {
                    nonceIndex = i;
                }

                if (counter == 2) {
                    nonce = new String(Arrays.copyOfRange(messageBytes, nonceIndex + 1, i));
                    actualMessage = Arrays.copyOfRange(messageBytes, i + 1, messageBytes.length);
                    break;
                }
            }

            if (!nounceList.contains(nonce))
                nounceList.add(nonce);
            else {
                throw new DuplicatedNonceException();
            }

            return actualMessage;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private List<byte[]> encodePayloadToAS(byte[] hashedPassword, DatagramPacket packet) throws IOException {

        try {
            //get ciphersuite from config file [0] -> payload ciphersuite | [1] -> hMAC ciphersuite
            String[] ciphersuite = ReadFromConfigs.readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
            String provider = ReadFromConfigs.readFromStgcSapAuth(AUTH_PROVIDER);

            c = Cipher.getInstance(ciphersuite[0], provider);

            PBEKeySpec pbeSpec = new PBEKeySpec(Hex.toHexString(hashedPassword).toCharArray(), salt, iterationCount);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
            Key sKey = keyFact.generateSecret(pbeSpec);

            c.init(c.ENCRYPT_MODE, sKey);

            //Build nounce, ipmc, sha-512(pwd) and MACk(X)
            ByteArrayOutputStream authC = new ByteArrayOutputStream();

            byte[] nonce = generateNounce(STGC_SAP);

            while (nounceList.contains(nonce)) {
                nonce = generateNounce(STGC_SAP);
            }

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
            MessageDigest messageDigest = MessageDigest.getInstance(DEFAULT_MD5, PROVIDER_BEFORE_TICKET);

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

            List<byte[]> response = new ArrayList<byte[]>(2);
            response.add(full.toByteArray());
            response.add(nonce);

            return response;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private TicketAS decodePayloadFromAS(byte[] data, byte[] nonce, byte[] hashedPassword) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IOException, BadPaddingException, IllegalBlockSizeException {
        String[] ciphersuite = ReadFromConfigs.readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
        String provider = ReadFromConfigs.readFromStgcSapAuth(AUTH_PROVIDER);
        
        byte[] nounceTmp = new byte[20];
        byte[] responseNounce;
        TicketAS t = null;
        
        //Was encoded as String, so needs to be transformed to String before
        BigInteger nouncePlus = new BigInteger(new String(nonce));
        nouncePlus = nouncePlus.add(BigInteger.ONE);

        ByteArrayOutputStream pbeKey = new ByteArrayOutputStream();

        pbeKey.write(hashedPassword);
        pbeKey.write(SEPARATOR);
        pbeKey.write(nouncePlus.toString().getBytes());

        c = Cipher.getInstance(ciphersuite[0], provider);
        PBEKeySpec pbeSpec = new PBEKeySpec(Hex.toHexString(pbeKey.toByteArray()).toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
        Key sKey = keyFact.generateSecret(pbeSpec);


        c.init(c.DECRYPT_MODE, sKey);
        data = c.doFinal(data);

        MessageDigest messageDigest = MessageDigest.getInstance(DEFAULT_MD5, PROVIDER_BEFORE_TICKET);
 
        int counter = 0;
        int lastIndex = 0;

        for (int i = 0; i < data.length; i++) {
            if (data[i] == SEPARATOR) {
                if (counter < 3) {
                    if (counter == 0) {
                        nounceTmp = Arrays.copyOfRange(data, lastIndex, i);
                        if (!messageDigest.isEqual(nouncePlus.toString().getBytes(), nounceTmp)) {
                            throw new MessageIntegrityBrokenException();
                        }
                        lastIndex = i + 1;
                        counter++;
                    } else {
                        if (counter == 1) {
                            responseNounce = Arrays.copyOfRange(data, lastIndex, i);
                            if (nounceList.contains(responseNounce)) {
                                throw new DuplicatedNonceException();
                            }
                            

                            ByteArrayOutputStream reply_NoTicket = new ByteArrayOutputStream();
                            reply_NoTicket.write(nounceTmp);
                            reply_NoTicket.write(SEPARATOR);
                            reply_NoTicket.write(responseNounce);
                            
                            byte[] hMd5 = messageDigest.digest(reply_NoTicket.toByteArray());
                           
                            Mac hMac = Mac.getInstance(ciphersuite[1], provider);
                            SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);

                            byte[] core = Arrays.copyOf(data, data.length - hMac.getMacLength());
                            byte[] hMacString = Arrays.copyOfRange(data, core.length, data.length);

                            hMac.init(keySpec);

                            if (!messageDigest.isEqual(hMac.doFinal(core), hMacString)) {
                                throw new MessageIntegrityBrokenException();
                            }

                            lastIndex = i + 1;
                            byte[] ticket = Arrays.copyOfRange(data, lastIndex, core.length - 1);
                            t = new TicketAS(ticket);
                            break;
                        }
                    }
                }
            }
        }
        
        System.out.println("Ticket Received Successfully");

        return t;
    }

    private byte[] generateNounce(char type) {
        return Nonce.randomNonce(type).getBytes();
    }
}
