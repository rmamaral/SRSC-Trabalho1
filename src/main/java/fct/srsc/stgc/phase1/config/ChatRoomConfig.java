package fct.srsc.stgc.phase1.config;

public class ChatRoomConfig {

    private String ip;
    private String ciphersuite;
    private String provider;
    private String keySize;
    private String keyValue;
    private String macKm;
    private String macKmKeySize;
    private String macKmKeyValue;
    private String macKa;
    private String macKaKeySize;
    private String macKaKeyValue;

    public ChatRoomConfig() {
    }

    public ChatRoomConfig(String ip, String ciphersuite, String provider, String keySize, String keyValue, String macKm, String macKmKeySize, String macKmKeyValue, String macKa, String macKaKeySize, String macKaKeyValue) {
        this.ip = ip;
        this.ciphersuite = ciphersuite;
        this.provider = provider;
        this.keySize = keySize;
        this.keyValue = keyValue;
        this.macKm = macKm;
        this.macKmKeySize = macKmKeySize;
        this.macKmKeyValue = macKmKeyValue;
        this.macKa = macKa;
        this.macKaKeySize = macKaKeySize;
        this.macKaKeyValue = macKaKeyValue;
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

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
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

    public String getMacKm() {
        return macKm;
    }

    public void setMacKm(String macKm) {
        this.macKm = macKm;
    }

    public String getMacKmKeySize() {
        return macKmKeySize;
    }

    public void setMacKmKeySize(String macKmKeySize) {
        this.macKmKeySize = macKmKeySize;
    }

    public String getMacKmKeyValue() {
        return macKmKeyValue;
    }

    public void setMacKmKeyValue(String macKmKeyValue) {
        this.macKmKeyValue = macKmKeyValue;
    }

    public String getMacKa() {
        return macKa;
    }

    public void setMacKa(String macKa) {
        this.macKa = macKa;
    }

    public String getMacKaKeySize() {
        return macKaKeySize;
    }

    public void setMacKaKeySize(String macKaKeySize) {
        this.macKaKeySize = macKaKeySize;
    }

    public String getMacKaKeyValue() {
        return macKaKeyValue;
    }

    public void setMacKaKeyValue(String macKaKeyValue) {
        this.macKaKeyValue = macKaKeyValue;
    }
}

