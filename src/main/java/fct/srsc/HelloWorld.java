package fct.srsc;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class HelloWorld {


    public static void main(String[] args) throws IOException {

        Properties prop = new Properties();
        InputStream input = HelloWorld.class.getClass().getResourceAsStream("/phase2/as/dacl.conf");

        // load a properties file
        prop.load(input);

        List x = Arrays.asList(prop.getProperty("239.9.9.9").split(";"));

        x.stream().forEach(it -> System.out.println(it));
    }
}
