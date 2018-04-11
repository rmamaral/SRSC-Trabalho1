package fct.srsc.stgc.phase1;

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
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;
import fct.srsc.stgc.phase1.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase1.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase1.utils.Nonce;

public class STGCMulticastSocket extends MulticastSocket {

	private static final String VERSION = "0";
	private static final String RELEASE = "1";

	private static final int HEADER_SIZE = 6;
	private static final int MAX_SIZE = 65536;

	private static final byte SEPARATOR = 0x00;

	private ChatRoomConfig config;
	private Cipher c;
	private int id = 1;
	private List<String> nounceList;
	
	private String groupAddress;
	private String username;

	public STGCMulticastSocket(String groupAddress, boolean authenticationServer, String username) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		super();
		init(groupAddress, authenticationServer,username);
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
		config = ReadFromConfig.readFromConfig(groupAddress);

		if(authenticationServer) {
			System.out.println("authServer: " + authenticationServer);
		}
		else {
			
			c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());
			nounceList = new ArrayList<String>();
			DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
			this.username = username;
			this.groupAddress = groupAddress;
			sendToAS(p, 'S');
		}
	}

	
	@Override
	public void send(DatagramPacket packet) throws IOException {
		System.out.println("Sending message through secure channel");

		Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());

		byte[] payload = encodePayload(key64, packet);//c.doFinal(packet.getData());

		byte[] header = buildHeader(payload.length, 'M');

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
	
	public void sendToAS(DatagramPacket packet, char type) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		System.out.println("Sending message to AS");

		//Key key64 = getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray());
		String password = "password";
				
		byte[] payload = encodePayloadToAS(password, packet);//c.doFinal(packet.getData());

		byte[] header = buildHeader(payload.length, type);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(header);
		outputStream.write(SEPARATOR);
		outputStream.write(payload);

		//Setting encrypted data and length to packet
		packet.setData(outputStream.toByteArray());
		packet.setLength(outputStream.size());

		super.send(packet);
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

	private byte[] encodePayloadToAS(String password, DatagramPacket packet) throws IOException {

		try {

		    MessageDigest   hash = MessageDigest.getInstance("SHA-512", "BC");
		        
		    hash.update(password.getBytes());
			
			PBEKeySpec          pbeSpec = new PBEKeySpec(Base64.getEncoder().encodeToString(hash.digest()).toCharArray());
	        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
	        Key    				sKey = keyFact.generateSecret(pbeSpec);
	        
	        c.init(c.ENCRYPT_MODE, sKey);
	    	
			//Build nounce, ipmc, sha-512(pwd) and MACk(X)
			ByteArrayOutputStream authC = new ByteArrayOutputStream();
			
			byte[] nounce = generateNounce();
			
			authC.write(nounce);
			authC.write(SEPARATOR);
			authC.write(this.groupAddress.getBytes());
			authC.write(SEPARATOR);
			authC.write(hash.digest());
			authC.write(SEPARATOR);
			
			
			ByteArrayOutputStream authC_NoIPMC = new ByteArrayOutputStream();
			authC_NoIPMC.write(nounce);
			authC_NoIPMC.write(SEPARATOR);
			authC_NoIPMC.write(hash.digest());
			authC_NoIPMC.write(SEPARATOR);
			
			//Create mac of authC
			MessageDigest   hashMd5 = MessageDigest.getInstance("md5", "BC");
		        
		    hashMd5.update(authC.toByteArray());
			Mac hMac = Mac.getInstance(config.getMacKm(), config.getProvider());
			PBEKeySpec          pbeSpec2 = new PBEKeySpec(Base64.getEncoder().encodeToString(hashMd5.digest()).toCharArray());
	        SecretKeyFactory    keyFact2 = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
			Key hMacKey = keyFact2.generateSecret(pbeSpec2);

			hMac.init(hMacKey);
			hMac.update(authC_NoIPMC.toByteArray());

			//Add mp hash
			authC.write(hMac.doFinal());

			//Cipher mp + hash
			c.init(Cipher.ENCRYPT_MODE, sKey);
			byte[] ecryptedCore = c.doFinal(authC.toByteArray());

			//Build Final -> clientId, NounceC, IPMC, AuthC
			ByteArrayOutputStream full = new ByteArrayOutputStream();
			full.write(this.username.getBytes());
			full.write(SEPARATOR);
			full.write(nounce);
			full.write(SEPARATOR);
			full.write(this.groupAddress.getBytes());
			full.write(SEPARATOR);
			full.write(ecryptedCore);
			
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
