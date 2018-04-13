package fct.srsc.authenticationServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.ReadFromConfig;
import fct.srsc.stgc.phase2.exceptions.AccessDeniedException;
import fct.srsc.stgc.phase2.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase2.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.phase2.model.AuthenticatorC;
import fct.srsc.stgc.phase2.model.TicketAS;
import fct.srsc.stgc.utils.Nonce;
import fct.srsc.stgc.utils.ReadFromConfigs;

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

	public byte[] decryptMessage (AuthenticationRequest ar) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		if(nounceList.contains(ar.getNonce())) {
			throw new DuplicatedNonceException();
		}
		else if(!verifyUserAuth(ar.getIpmc(),ar.getUsername())){
			throw new AccessDeniedException(String.format("%s is not allowed in the requested chat room", ar.getUsername()));
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
	}


	public void verifySignature(AuthenticationRequest ar, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException {

		String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
		String provider = readFromStgcSapAuth(AUTH_PROVIDER);

		Mac hMac = Mac.getInstance(ciphersuite[1], provider);

		AuthenticatorC authC = buildAuthC(data);

		ByteArrayOutputStream authC_NoIPMC = new ByteArrayOutputStream();
		authC_NoIPMC.write(authC.getNonce());
		authC_NoIPMC.write(SEPARATOR);
		authC_NoIPMC.write(authC.getHp());
		authC_NoIPMC.write(SEPARATOR);

		MessageDigest messageDigest = MessageDigest.getInstance("md5", "BC");

		byte[] hMd5 = messageDigest.digest(authC_NoIPMC.toByteArray());
		SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);
		hMac.init(keySpec);


		if(!Base64.getEncoder().encodeToString(hMac.doFinal(authC.buildCore())).equals(Base64.getEncoder().encodeToString(authC.getMac()))
				|| !ar.getNonce().equals(new String(authC.getNonce())) || !ar.getIpmc().equals(new String(authC.getIpmc()))) {
			throw new MessageIntegrityBrokenException();
		}
	}

	public byte[] encrypt(AuthenticationRequest ar) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub

		String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
		String provider = readFromStgcSapAuth(AUTH_PROVIDER);
		byte[] pwdHash = Hex.decode(getPwdHash(ar.getUsername()));

		
		//build core

		BigInteger nonce = new BigInteger(ar.getNonce());
		BigInteger nonceBig = nonce.add(BigInteger.ONE);
		byte[] nonceC = nonceBig.toString().getBytes();

		byte[] nounceS = generateNounce('S');
		while(nounceList.contains(nounceS)) {
			nounceS = generateNounce('S');
		}

		TicketAS ticket = buildTicket(ar.getIpmc());

		ByteArrayOutputStream reply = new ByteArrayOutputStream();

		reply.write(nonceC);
		reply.write(SEPARATOR);
		reply.write(nounceS);
		reply.write(SEPARATOR);
		reply.write(ticket.buildCore());

		//mount pbe key -> hpwd + || + nounceC+1
		ByteArrayOutputStream pbeKey = new ByteArrayOutputStream();

		pbeKey.write(pwdHash);
		pbeKey.write(SEPARATOR);
		pbeKey.write(nonceC);

		c = Cipher.getInstance(ciphersuite[0], provider);
	
		PBEKeySpec pbeSpec = new PBEKeySpec(Hex.toHexString(pbeKey.toByteArray()).toCharArray(), salt, iterationCount);
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
		Key sKey = keyFact.generateSecret(pbeSpec);

		
		//Create mac of reply
		MessageDigest messageDigest = MessageDigest.getInstance("md5", "BC");

		//MISSING MAC KEY
		byte[] hMd5 = messageDigest.digest("password".getBytes());
		Mac hMac = Mac.getInstance(ciphersuite[1], provider);
		SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);

		hMac.init(keySpec);
		
		reply.write(SEPARATOR);
		reply.write(hMac.doFinal(reply.toByteArray()));

		c.init(c.ENCRYPT_MODE, sKey);
		byte[] encCore = c.doFinal(reply.toByteArray());
				
		return encCore;
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
	
	private TicketAS buildTicket(String ipmc){
		
		ChatRoomConfig crConf = ReadFromConfig.readFromConfig(ipmc);
		
		byte[] ks = ReadFromConfigs.getKeyFromKeyStore("JCEKS", "mykeystore.jks", "mykey1", "password".toCharArray(), "password".toCharArray()).getEncoded();
		byte[] kmAlgorithm = crConf.getMacKm().getBytes(); 
		byte[] km = ReadFromConfigs.getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macInKey", "password".toCharArray(), "password".toCharArray()).getEncoded();
		byte[] kaAlgorithm = crConf.getMacKa().getBytes(); 
		byte[] ka = ReadFromConfigs.getKeyFromKeyStore("JCEKS", "mykeystore.jks", "macOutKey", "password".toCharArray(), "password".toCharArray()).getEncoded();
		
		//5 min expire time
		TicketAS t = new TicketAS(crConf.getCiphersuite().getBytes(), ks, kmAlgorithm, km, kaAlgorithm, ka, System.currentTimeMillis()+(5*60*1000));
		
		return t;
	}

	private byte[] generateNounce(char type) {
		return Nonce.randomNonce(type).getBytes();
	}

	private AuthenticatorC buildAuthC (byte[] data) {
		int lastIndex = 0;
		int counter = 0;
		AuthenticatorC ar = new AuthenticatorC();

		for (int i = 0; i < data.length; i++) {
			if (data[i] == SEPARATOR) {
				if (counter < 3) {
					if (counter == 0) {
						ar.setNonce(Arrays.copyOfRange(data, lastIndex, i));
						lastIndex = i + 1;
						counter++;
					} else {
						if (counter == 1) {
							ar.setIpmc(Arrays.copyOfRange(data, lastIndex, i));
							lastIndex = i + 1;
							counter++;
						} else {
							if (counter == 2) {
								ar.setHp(Arrays.copyOfRange(data, lastIndex, i));
								lastIndex = i + 1;
								ar.setMac(Arrays.copyOfRange(data, lastIndex, data.length));
								break;
							}
						}
					}
				}
			}
		}
		return ar;
	}
}
