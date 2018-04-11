package fct.srsc;

import fct.srsc.stgc.utils.Nonce;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

public class HelloWorld {


    public static void main(String[] args) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {

        /*Properties prop = new Properties();
        InputStream input = HelloWorld.class.getClass().getResourceAsStream("/phase2/as/users.conf");

        // load a properties file
        prop.load(input);


        MessageDigest md = MessageDigest.getInstance("SHA-512", "BC");
        String reis = "I<3BaNanA5!";

        byte [] x = md.digest(reis.getBytes());
        System.out.println(Hex.toHexString(x).equals(prop.getProperty("reis"))? true : false);*/

        BigInteger x = new BigInteger(Nonce.randomNonce('S'));
        System.out.println(x);

        BigInteger y = x.add(BigInteger.ONE);
        System.out.println(y);
    }
}
