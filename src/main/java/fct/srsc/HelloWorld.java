package fct.srsc;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.Configurations;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class HelloWorld {


    public static void main(String[] args) throws IOException {

        short c = 1;

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(c);

        System.out.println(outputStream.toByteArray().length);
    }
}
