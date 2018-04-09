package fct.srsc.stgc.phase1.config;

import java.util.List;

public class Configurations {

    private List<ChatRoomConfig> configs;

    public Configurations() {
    }

    public Configurations(List<ChatRoomConfig> configs) {
        this.configs = configs;
    }

    public void setConfigs(List<ChatRoomConfig> configs) {
        this.configs = configs;
    }

    public List<ChatRoomConfig> getConfigs () {
        return this.configs;
    }

    public ChatRoomConfig getChatRoomConfig (String group) {
        for (ChatRoomConfig crc : configs){
            if (crc.getIp().equals(group)){
                return crc;
            }
        }
        return null;
    }
}