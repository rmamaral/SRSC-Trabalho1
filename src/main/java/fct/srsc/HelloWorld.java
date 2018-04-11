package fct.srsc;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.Configurations;

import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class HelloWorld {


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException {


		PBEKeySpec          pbeSpec = new PBEKeySpec("passworisjdiasadasdasdsjd".toCharArray());
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key    sKey = keyFact.generateSecret(pbeSpec);
        
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES","BC");
        String          input = "pasdasasswordasdasasdasddasd";

        MessageDigest   hash = MessageDigest.getInstance("MD5", "BC");
        
        hash.update(input.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(hash.digest()));
    	
    	
    	
    	
    	
        //Build mp, id nonce and message
        ByteArrayOutputStream mp = new ByteArrayOutputStream();

        String dateTimeString = Long.toString(new Date().getTime());

        mp.write(Integer.toString(1).getBytes());
        mp.write('|');
        mp.write("wd".getBytes());
        mp.write('|');
        mp.write("qsd".getBytes());

        byte[] y = mp.toByteArray();

        for (int i = 0; i<y.length; i++){
            if(y[i]=='|')
                System.out.println("HILLO");
        }
    }
}
