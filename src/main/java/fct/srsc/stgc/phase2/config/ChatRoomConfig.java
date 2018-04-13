package fct.srsc.stgc.phase2.config;

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
    private String keyStoreType;
    private String keyStoreName;
    private String keyName;
    private String keyPassword;
    private String keyStorePassword;

    public ChatRoomConfig() {
    }

    public ChatRoomConfig(String ip, String ciphersuite, String provider, String keySize, String keyValue, String macKm, String macKmKeySize, String macKmKeyValue, String macKa, String macKaKeySize, String macKaKeyValue, String keyStoreType, String keyStoreName, String keyName, String keyPassword, String keyStorePassword) {
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
        this.keyStoreType = keyStoreType;
        this.keyStoreName = keyStoreName;
        this.keyName = keyName;
        this.keyPassword = keyPassword;
        this.keyStorePassword = keyStorePassword;
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

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStoreName() {
        return keyStoreName;
    }

    public void setKeyStoreName(String keyStoreName) {
        this.keyStoreName = keyStoreName;
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }
}

