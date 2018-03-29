package fct.srsc;

import fct.srsc.stgc.phase1.config.ChatRoomConfig;
import fct.srsc.stgc.phase1.config.Configurations;
import org.yaml.snakeyaml.Yaml;
import java.io.InputStream;

public class HelloWorld {


    public static void main(String[] args) {
        Yaml yaml = new Yaml();
        try{
            InputStream in = HelloWorld.class.getClass().getResourceAsStream("/phase1/config.yml");

             Configurations configs = yaml.loadAs(in, Configurations.class);

             for (ChatRoomConfig conf : configs.getConfigs()){
                 System.out.println(conf.getCiphersuite());
             }

            System.out.println("238.69.69.69: " + configs.getChatRoomConfig("238.69.69.69").getIp());

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
