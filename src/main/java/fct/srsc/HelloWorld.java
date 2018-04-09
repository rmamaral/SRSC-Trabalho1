package fct.srsc;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.Configurations;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Date;

public class HelloWorld {


    public static void main(String[] args) throws IOException {

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
