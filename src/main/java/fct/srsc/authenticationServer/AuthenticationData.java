package fct.srsc.authenticationServer;

import fct.srsc.stgc.phase2.config.ChatRoomConfig;
import fct.srsc.stgc.phase2.exceptions.AccessDeniedException;
import fct.srsc.stgc.phase2.exceptions.DuplicatedNonceException;
import fct.srsc.stgc.phase2.exceptions.MessageIntegrityBrokenException;
import fct.srsc.stgc.phase2.model.AuthenticationRequest;
import fct.srsc.stgc.phase2.model.AuthenticatorC;
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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class AuthenticationData {

    private static final byte SEPARATOR = 0x00;
    private static final String AUTH_CIPHERSUITE = "STGC-SAP";
    private static final char STGC_SAP_TYPE = 'S';
    private static final String AUTH_PROVIDER = "PROVIDER";

    private static final String DEFAULT_PROVIDER = "BC";
    private static final String DEFAULT_SHA = "SHA-512";
    private static final String DEFAULT_MD5 = "md5";

    private static final byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
    private static final int iterationCount = 2048;

    private List<byte[]> nounceList;
    private Cipher c;

    public AuthenticationData() {
        this.nounceList = new ArrayList<byte[]>();
    }

    public List<byte[]> getNounceList() {
        return nounceList;
    }

    public byte[] decryptMessage(AuthenticationRequest ar) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        if (nounceList.contains(ar.getNonce())) {
            throw new DuplicatedNonceException();
        } else if (!verifyUserAuth(ar.getIpmc(), ar.getUsername())) {
            throw new AccessDeniedException(String.format("%s is not allowed in the requested chat room", ar.getUsername()));
        } else {
            String pwdHash = ReadFromConfigs.readKeyFromConfig(ar.getUsername());

            //get ciphersuite from config file [0] -> payload ciphersuite | [1] -> hMAC ciphersuite
            String[] ciphersuite = ReadFromConfigs.readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
            String provider = ReadFromConfigs.readFromStgcSapAuth(AUTH_PROVIDER);

            c = Cipher.getInstance(ciphersuite[0], provider);
            PBEKeySpec pbeSpec = new PBEKeySpec(pwdHash.toCharArray(), salt, iterationCount);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ciphersuite[0], provider);
            Key sKey = keyFact.generateSecret(pbeSpec);

            try {
                c.init(c.DECRYPT_MODE, sKey);
                byte[] data = c.doFinal(ar.getAuthenticatorC());
                return data;
            } catch (InvalidKeyException invKey) {
                System.out.println("Invalid Key!");
            }

            return null;
        }
    }


    public void verifySignature(AuthenticationRequest ar, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException {

        String[] ciphersuite = ReadFromConfigs.readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
        String provider = ReadFromConfigs.readFromStgcSapAuth(AUTH_PROVIDER);

        Mac hMac = Mac.getInstance(ciphersuite[1], provider);

        AuthenticatorC authC = new AuthenticatorC(data);

        ByteArrayOutputStream authC_NoIPMC = new ByteArrayOutputStream();
        authC_NoIPMC.write(authC.getNonce());
        authC_NoIPMC.write(SEPARATOR);
        authC_NoIPMC.write(authC.getHp());
        authC_NoIPMC.write(SEPARATOR);

        MessageDigest messageDigest = MessageDigest.getInstance(DEFAULT_MD5, DEFAULT_PROVIDER);

        byte[] hMd5 = messageDigest.digest(authC_NoIPMC.toByteArray());
        SecretKeySpec keySpec = new SecretKeySpec(hMd5, ciphersuite[1]);
        hMac.init(keySpec);


        if (!Base64.getEncoder().encodeToString(hMac.doFinal(authC.buildCore())).equals(Base64.getEncoder().encodeToString(authC.getMac()))
                || !ar.getNonce().equals(new String(authC.getNonce())) || !ar.getIpmc().equals(new String(authC.getIpmc()))) {
            throw new MessageIntegrityBrokenException();
        }
    }

    public byte[] encrypt(AuthenticationRequest ar) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        String[] ciphersuite = ReadFromConfigs.readFromStgcSapAuth(AUTH_CIPHERSUITE).split(":");
        String provider = ReadFromConfigs.readFromStgcSapAuth(AUTH_PROVIDER);
        byte[] pwdHash = Hex.decode(ReadFromConfigs.readKeyFromConfig(ar.getUsername()));


        //build core

        BigInteger nonce = new BigInteger(ar.getNonce());
        BigInteger nonceBig = nonce.add(BigInteger.ONE);
        byte[] nonceC = nonceBig.toString().getBytes();

        byte[] nounceS = generateNounce(STGC_SAP_TYPE);
        while (nounceList.contains(nounceS)) {
            nounceS = generateNounce(STGC_SAP_TYPE);
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
        MessageDigest messageDigest = MessageDigest.getInstance(DEFAULT_MD5, DEFAULT_PROVIDER);

        //MAC KEY
        
        ByteArrayOutputStream reply_NoTicket = new ByteArrayOutputStream();
        reply_NoTicket.write(nonceC);
        reply_NoTicket.write(SEPARATOR);
        reply_NoTicket.write(nounceS);
        
        byte[] hMd5 = messageDigest.digest(reply_NoTicket.toByteArray());
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

        String[] splited = ReadFromConfigs.readFromDaclAuth(ipmc).split(";");

        for (int i = 0; i < splited.length; i++) {
            if (splited[i].equals(username)) {
                return true;
            }
        }
        return false;
    }

    private TicketAS buildTicket(String ipmc) {

        ChatRoomConfig crConf = ReadFromConfigs.readFromConfig(ipmc);

        byte[] provider = crConf.getProvider().getBytes();
        byte[] ks = ReadFromConfigs.getKeyFromKeyStore(crConf.getKeyStoreType(), crConf.getKeyStoreName(), crConf.getKeyName(), crConf.getKeyPassword().toCharArray(), crConf.getKeyStorePassword().toCharArray()).getEncoded();
        ks = Base64.getEncoder().encodeToString(ks).getBytes();

        byte[] kmAlgorithm = crConf.getMacKm().getBytes();
        byte[] km = ReadFromConfigs.getKeyFromKeyStore(crConf.getKeyStoreType(), crConf.getKeyStoreName(), crConf.getKeyName(), crConf.getKeyPassword().toCharArray(), crConf.getKeyStorePassword().toCharArray()).getEncoded();
        km = Base64.getEncoder().encodeToString(km).getBytes();

        byte[] kaAlgorithm = crConf.getMacKa().getBytes();
        byte[] ka = ReadFromConfigs.getKeyFromKeyStore(crConf.getKeyStoreType(), crConf.getKeyStoreName(), crConf.getKeyName(), crConf.getKeyPassword().toCharArray(), crConf.getKeyStorePassword().toCharArray()).getEncoded();
        ka = Base64.getEncoder().encodeToString(ka).getBytes();

        //5 min expire time
        TicketAS t = new TicketAS(crConf.getCiphersuite().getBytes(), ks, kmAlgorithm, km, kaAlgorithm, ka, System.currentTimeMillis() + (5 * 60 * 1000), provider);

        return t;
    }

    private byte[] generateNounce(char type) {
        return Nonce.randomNonce(type).getBytes();
    }
}
