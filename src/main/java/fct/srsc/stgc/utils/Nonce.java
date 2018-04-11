package fct.srsc.stgc.utils;

import java.security.SecureRandom;
import java.util.Random;

public class Nonce {

    private final static String AB = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-/?!_.,:;(){}[]";
    private final static int nonceLength = 20;
    private static Random rnd = new SecureRandom();

    public static String randomString(  ){
        StringBuilder sb = new StringBuilder( nonceLength );
        for( int i = 0; i < nonceLength; i++ )
            sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
        return sb.toString();
    }
}