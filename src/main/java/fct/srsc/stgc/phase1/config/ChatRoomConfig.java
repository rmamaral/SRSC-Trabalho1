package fct.srsc.stgc.phase1.config;

public class ChatRoomConfig {

    private String ip;
    private String ciphersuite;
    private String keySize;
    private String keyValue;
    private String mac;
    private String macKeySize;
    private String macKeyValue;

    public ChatRoomConfig() {
    }

    public ChatRoomConfig(String ip, String ciphersuite, String keySize, String keyValue, String mac, String macKeySize, String macKeyValue) {
        this.ip = ip;
        this.ciphersuite = ciphersuite;
        this.keySize = keySize;
        this.keyValue = keyValue;
        this.mac = mac;
        this.macKeySize = macKeySize;
        this.macKeyValue = macKeyValue;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getCiphersuite() {
        return ciphersuite;
    }

    public void setCiphersuite(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public String getKeySize() {
        return keySize;
    }

    public void setKeySize(String keySize) {
        this.keySize = keySize;
    }

    public String getKeyValue() {
        return keyValue;
    }

    public void setKeyValue(String keyValue) {
        this.keyValue = keyValue;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getMacKeySize() {
        return macKeySize;
    }

    public void setMacKeySize(String macKeySize) {
        this.macKeySize = macKeySize;
    }

    public String getMacKeyValue() {
        return macKeyValue;
    }

    public void setMacKeyValue(String macKeyValue) {
        this.macKeyValue = macKeyValue;
    }
}

