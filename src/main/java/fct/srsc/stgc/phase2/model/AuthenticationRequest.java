package fct.srsc.stgc.phase2.model;

public class AuthenticationRequest {

    private String username;
    private String nonce;
    private String ipmc;
    private byte[] authenticatorC;

    public AuthenticationRequest() {
    }

    public AuthenticationRequest(String username, String nonce, String ipmc, byte[] authenticatorC) {
        this.username = username;
        this.nonce = nonce;
        this.ipmc = ipmc;
        this.authenticatorC = authenticatorC;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getIpmc() {
        return ipmc;
    }

    public void setIpmc(String ipmc) {
        this.ipmc = ipmc;
    }

    public byte[] getAuthenticatorC() {
        return authenticatorC;
    }

    public void setAuthenticatorC(byte[] authenticatorC) {
        this.authenticatorC = authenticatorC;
    }
}
