package fct.srsc.stgc.phase1.config;

import java.io.InputStream;

import org.yaml.snakeyaml.Yaml;

public class ReadFromConfig {

    private static final String configFile = "phase1/config.yml";

    public static ChatRoomConfig readFromConfig (String groupAddress) {
        Yaml yaml = new Yaml();

        try{
            InputStream in = ReadFromConfig.class.getClass().getResourceAsStream("/phase1/config.yml");
            Configurations configs = yaml.loadAs(in, Configurations.class);
            return configs.getChatRoomConfig(groupAddress);

        }catch (Exception e){
            return null;
        }
    }


}
