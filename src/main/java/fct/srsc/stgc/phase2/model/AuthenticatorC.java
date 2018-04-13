package fct.srsc.stgc.phase2.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class AuthenticatorC {

    private byte[] nonce;
    private byte[] ipmc;
    private byte[] hp;
    private byte[] mac;

    public AuthenticatorC() {
    }

    public AuthenticatorC(byte[] nonce, byte[] ipmc, byte[] hp, byte[] mac) {
        this.nonce = nonce;
        this.ipmc = ipmc;
        this.hp = hp;
        this.mac = mac;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public byte[] getIpmc() {
        return ipmc;
    }

    public void setIpmc(byte[] ipmc) {
        this.ipmc = ipmc;
    }

    public byte[] getHp() {
        return hp;
    }

    public void setHp(byte[] hp) {
        this.hp = hp;
    }

    public byte[] getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = mac;
    }

    public byte [] buildCore () throws IOException {
        ByteArrayOutputStream core = new ByteArrayOutputStream();
        core.write(getNonce());
        core.write(0x00);
        core.write(getIpmc());
        core.write(0x00);
        core.write(getHp());
        core.write(0x00);
        return core.toByteArray();
    }
}
