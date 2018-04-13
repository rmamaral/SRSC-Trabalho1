package fct.srsc.stgc.phase2;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketAddress;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
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

import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.utils.Nonce;

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

			try {
				establishSecureConnection(groupAddress, username);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			//receiveReplyFromAS ();

			//c = Cipher.getInstance(config.getCiphersuite(), config.getProvider());

		}
	}


	private void establishSecureConnection(String groupAddress, String username) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidKeyException {
		this.username = username;
		this.groupAddress = groupAddress;

		byte[] nounce = connectAuthenticationServer();
		//TODO: wait for answer of authentication server and process that reply

		DatagramPacket p = new DatagramPacket(new byte[65536], 65536);
		p.setLength(65536);
		System.out.println("Waiting for AuthServer response....");
		super.receive(p);

		System.out.println("Received response from AuthServer");
		byte [] data = new byte[p.getLength()];
		System.arraycopy(p.getData(), 0, data, 0, p.getLength());
		decodePayloadFromAS(data, nounce);
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

	public byte[] connectAuthenticationServer() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		System.out.println("Establishing Secure Connection");

		//TODO: For now hardcoded -> ask professor how it is passed
		MessageDigest md = MessageDigest.getInstance("SHA-512", "BC");
		byte[] hashedPassword = Hex.decode(readKeyFromConfig(username));


		DatagramPacket packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

		//TODO delete this initialization
		byte[] payload = new byte[1];
		List<byte[]> payloadWithNounce = new ArrayList<byte[]>(2);
		if (!authenticationServer) {
			payloadWithNounce = encodePayloadToAS(hashedPassword, packet);//c.doFinal(packet.getData());
			payload = payloadWithNounce.get(0);
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

		super.send(packet);
		System.out.println("Request to AuthServer sent");

		return payloadWithNounce.get(1);
	}

	public void sendToClient(byte[] p, InetAddress clientAddress, int port) {
		try {

			DatagramPacket packet = new DatagramPacket(new byte[65536], 65536);
			packet.setLength(p.length);
			packet.setData(p);

			packet.setAddress(clientAddress);
			packet.setPort(port);

			super.send(packet);
			System.out.println("sended from server to client");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public AuthenticationRequest receiveClientRequest(DatagramPacket packet) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
		super.receive(packet);
		System.out.println("Client request received");
		byte[] dataParts = Arrays.copyOfRange(packet.getData(), HEADER_SIZE + 1, packet.getLength());
		//TODO: Process Header --> Arrays.copyOf(packet.getData(), HEADER_SIZE);

		AuthenticationRequest ar = buildASRequest(dataParts, packet.getAddress(), packet.getPort());

		return ar;
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

	private List<byte[]> encodePayloadToAS(byte[] hashedPassword, DatagramPacket packet) throws IOException {

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

			while(nounceList.contains(nonce)) {
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

			List<byte[]> response = new ArrayList<byte[]>(2);
			response.add(full.toByteArray());
			response.add(nonce);
			return response;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	private void decodePayloadFromAS(byte[] data, byte[] nounce) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		// TODO Auto-generated method stub
		String[] ciphersuite = readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
		String provider = readFromStgcSapAuth(AUTH_PROVIDER);

		MessageDigest messageDigest = MessageDigest.getInstance("md5", "BC");
		byte[] hMd5 = messageDigest.digest("password".getBytes());
		Mac hMac = Mac.getInstance(ciphersuite[1], provider);
		SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);

		byte[] core = new byte[data.length - hMac.getMacLength()];
		byte[] hMacString = new byte[hMac.getMacLength()];

		core = Arrays.copyOfRange(data, 0, data.length - hMac.getMacLength());
		hMacString = Arrays.copyOfRange(data, data.length - hMac.getMacLength(), data.length);
		
		hMac.init(keySpec);
		hMac.update(core);
		
		System.out.println("ALL -> " + Base64.getEncoder().encodeToString(data));
		System.out.println("HMAC -> " + Base64.getEncoder().encodeToString(hMacString));
		System.out.println("CORE -> " + Base64.getEncoder().encodeToString(hMac.doFinal()));

		if(!messageDigest.isEqual(hMac.doFinal(), hMacString)) {
			System.out.println("message corrupted1");
		}
		else {

			int counter = 0;
			int lastIndex = 0;
			
			for (int i = 0; i < data.length; i++) {
				if (data[i] == SEPARATOR) {
					if (counter < 3) {
						if (counter == 0) {
							byte[] nouncePlus = Arrays.copyOfRange(data, lastIndex, i);
							if(!messageDigest.isEqual(nouncePlus, nounce)) {
								System.out.println("Message Corrupted2");
								break;
							}
							lastIndex = i + 1;
							counter++;
						} else {
							if (counter == 1) {
								byte[] responseNounce = Arrays.copyOfRange(data, lastIndex, i);
								if(nounceList.contains(responseNounce)) {
									System.out.println("Message Corrupted3");
									break;
								}
								lastIndex = i + 1;
								counter++;
							} else {
								if (counter == 2) {
									byte[] ticket = new byte[data.length-hMac.getMacLength()];
									System.arraycopy(data, i+1, ticket, 0, data.length-hMac.getMacLength());
									break;
								}
							}
						}
					}
				}	
			}
			
			//take care of ticket
			
			
		}
			
			


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

		private AuthenticationRequest buildASRequest(byte[] data, InetAddress address, int port) {
			int lastIndex = 0;
			int counter = 0;
			AuthenticationRequest ar = new AuthenticationRequest();
			ar.setClientAddress(address);
			ar.setClientPort(port);

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
