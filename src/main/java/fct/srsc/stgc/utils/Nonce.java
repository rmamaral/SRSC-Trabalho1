package fct.srsc.stgc.utils;

import java.security.SecureRandom;
import java.util.Random;

public class Nonce {

    private final static String STRING_NONCE = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-/?!_.,:;(){}[]";
    private final static String INTEGER_NONCE = "123456789";

    private final static int nonceLength = 20;
    private static Random rnd = new SecureRandom();

    public static String randomNonce (char type){
        String generationType = null;

        if(type=='M'){
            generationType = STRING_NONCE;
        }
        if(type=='S'){
            generationType = INTEGER_NONCE;
        }

        StringBuilder sb = new StringBuilder( nonceLength );
        for( int i = 0; i < nonceLength; i++ )
            sb.append( generationType.charAt( rnd.nextInt(generationType.length()) ) );
        return sb.toString();
    }
}
