package fct.srsc;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.Configurations;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public class HelloWorld {


    public static void main(String[] args) throws IOException {

        SecureRandom sr = new SecureRandom();
        byte [] nonce = new byte[512];
        sr.nextBytes(nonce);

        System.out.println(new String(nonce));
    }
}
