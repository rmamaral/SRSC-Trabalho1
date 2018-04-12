package fct.srsc.authenticationServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import fct.srsc.stgc.phase2.exceptions.UserNotRegisteredException;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.utils.Nonce;

public class AuthenticationData {

	private static final byte SEPARATOR = 0x00;
	private static final String AUTH_CIPHERSUITE = "STGC-SAP";
	private static final String AUTH_PROVIDER = "PROVIDER";

	private static final byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
	private static final int iterationCount = 2048;

	private List<byte[]> nounceList;
	private Cipher c;

	public AuthenticationData() {
		this.nounceList = new ArrayList<byte[]>(); 
	}

	public List<byte[]> getNounceList(){
		return nounceList;
	}

	public byte[] verifySignature (AuthenticationRequest ar) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		if(nounceList.contains(ar.getNonce())) {
			System.out.println("Duplicated message");	
		}
		else if(!verifyUserAuth(ar.getIpmc(),ar.getUsername())){
			System.out.println(ar.getUsername() + ", you're not allowed in this room!");
		}
		else {

			String pwdHash = getPwdHash(ar.getUsername());

			//get ciphersuite from config file [0] -> payload ciphersuite | [1] -> hMAC ciphersuite
			String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
			String provider = readFromStgcSapAuth(AUTH_PROVIDER);

			c = Cipher.getInstance(ciphersuite[0], provider);
			PBEKeySpec pbeSpec = new PBEKeySpec(pwdHash.toCharArray(), salt, iterationCount);
			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
			Key sKey = keyFact.generateSecret(pbeSpec);

			try {
				c.init(c.DECRYPT_MODE, sKey);
				byte[] data = c.doFinal(ar.getAuthenticatorC());
				return data;
			}
			catch(InvalidKeyException invKey) {
				System.out.println("Invalid Key!");
			}

			return null;
		}
		return null;
	}


	public boolean verifyMac(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException {
		// TODO Auto-generated method stub

		String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
		String provider = readFromStgcSapAuth(AUTH_PROVIDER);

		Mac hMac = Mac.getInstance(ciphersuite[1], provider);
		byte[] hMacData = new byte[hMac.getMacLength()];
		System.arraycopy(data, data.length - hMac.getMacLength(), hMacData, 0, hMac.getMacLength());		

		byte[] core = new byte[data.length - hMac.getMacLength()];				
		System.arraycopy(data, 0, core, 0, data.length - hMac.getMacLength());

		if(hMacData.equals(core)) {
			return true;
		}
		else {
			return false;
		}
	}

	public byte[] encrypt(AuthenticationRequest ar) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException {
		// TODO Auto-generated method stub

		String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
		String provider = readFromStgcSapAuth(AUTH_PROVIDER);
		String pwdHash = getPwdHash(ar.getUsername());

		
		//build core

		BigInteger nounce = new BigInteger(ar.getNonce());
		BigInteger nounceBig = nounce.add(BigInteger.ONE);
		byte[] nounceC = nounceBig.toByteArray();

		byte[] nounceS = generateNounce('S');
		while(nounceList.contains(nounceS)) {
			nounceS = generateNounce('S');
		}
		
		//MISSING DEFINE TICKET
		byte[] ticket = new byte[2];//TOciaesDO

		ByteArrayOutputStream reply = new ByteArrayOutputStream();

		reply.write(nounceC);
		reply.write(SEPARATOR);
		reply.write(nounceS);
		reply.write(SEPARATOR);
		reply.write(ticket);

		//mount pbe key -> hpwd + || + nounceC+1
		ByteArrayOutputStream pbeKey = new ByteArrayOutputStream();

		pbeKey.write(pwdHash.getBytes());
		pbeKey.write(SEPARATOR);
		pbeKey.write(nounceC);
	
		c = Cipher.getInstance(ciphersuite[0], provider);
	
		PBEKeySpec pbeSpec = new PBEKeySpec(Hex.toHexString(pbeKey.toByteArray()).toCharArray(), salt, iterationCount);
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
		Key sKey = keyFact.generateSecret(pbeSpec);

		c.init(c.ENCRYPT_MODE, sKey);

		//Create mac of reply
		MessageDigest messageDigest = MessageDigest.getInstance("md5", "BC");

		//MISSING MAC KEY
		byte[] hMd5 = messageDigest.digest("password".getBytes());
		Mac hMac = Mac.getInstance(ciphersuite[1], provider);
		SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);

		hMac.init(keySpec);
		hMac.update(reply.toByteArray());
		
		reply.write(hMac.doFinal());
		
		return reply.toByteArray();


	}

	public boolean verifyUserAuth(String ipmc, String username) {

		String[] splited = readFromDaclAuth(ipmc).split(";");

		for(int i = 0; i < splited.length; i++) {
			if(splited[i].equals(username)) {
				return true;
			}
		}
		return false;
	}

	public String readKeyFromConfig (String username) {
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


	public String readFromDaclAuth(String property) {
		try {
			Properties prop = new Properties();
			InputStream input = this.getClass().getResourceAsStream("/phase2/as/dacl.conf");

			prop.load(input);
			return prop.getProperty(property);

		}
		catch(IOException e) {
			e.printStackTrace();
			return null;
		}
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


	public String getPwdHash(String username) {
		// TODO Auto-generated method stub
		try {
			Properties prop = new Properties();
			InputStream input = this.getClass().getResourceAsStream("/phase2/as/users.conf");

			prop.load(input);
			String hashpassword = prop.getProperty(username);
			return hashpassword;

		}
		catch(IOException e) {
			e.printStackTrace();
			return "";
		}
	}

	private byte[] generateNounce(char type) {
		return Nonce.randomNonce(type).getBytes();
	}

}
