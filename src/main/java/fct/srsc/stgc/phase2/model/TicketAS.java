package fct.srsc.stgc.phase2.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class TicketAS {

    private static final byte SEPARATOR = 0x00;

    private byte[] ciphersuite;
    private byte[] ks;
    private byte[] kmAlgorithm;
    private byte[] km;
    private byte[] kaAlgorithm;
    private byte[] ka;
    private long expire;
    private byte[] provider;

    public TicketAS() {

    }

    public TicketAS(byte[] rawData) {
        buildTicket(rawData);
    }

    public TicketAS(byte[] ciphersuite, byte[] ks, byte[] kmAlgorithm, byte[] km, byte[] kaAlgorithm, byte[] ka, long expire, byte[] provider) {

        this.ciphersuite = ciphersuite;
        this.ks = ks;
        this.kmAlgorithm = kmAlgorithm;
        this.km = km;
        this.kaAlgorithm = kaAlgorithm;
        this.ka = ka;
        this.expire = expire;
        this.provider = provider;
    }

    public byte[] buildCore() throws IOException {
        ByteArrayOutputStream core = new ByteArrayOutputStream();
        core.write(ciphersuite);
        core.write(SEPARATOR);
        core.write(ks);
        core.write(SEPARATOR);
        core.write(kmAlgorithm);
        core.write(SEPARATOR);
        core.write(km);
        core.write(SEPARATOR);
        core.write(kaAlgorithm);
        core.write(SEPARATOR);
        core.write(ka);
        core.write(SEPARATOR);
        core.write(Long.toString(expire).getBytes());
        core.write(SEPARATOR);
        core.write(provider);
        //core.write(0x00);
        return core.toByteArray();
    }

    public byte[] getCiphersuite() {
        return ciphersuite;
    }

    public void setCiphersuite(byte[] ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] getKs() {
        return ks;
    }

    public void setKs(byte[] ks) {
        this.ks = ks;
    }

    public byte[] getKmAlgorithm() {
        return kmAlgorithm;
    }

    public void setKmAlgorithm(byte[] kmAlgorithm) {
        this.kmAlgorithm = kmAlgorithm;
    }

    public byte[] getKm() {
        return km;
    }

    public void setKm(byte[] km) {
        this.km = km;
    }

    public byte[] getKaAlgorithm() {
        return kaAlgorithm;
    }

    public void setKaAlgorithm(byte[] kaAlgorithm) {
        this.kaAlgorithm = kaAlgorithm;
    }

    public byte[] getKa() {
        return ka;
    }

    public void setKa(byte[] ka) {
        this.ka = ka;
    }

    public long getExpire() {
        return expire;
    }

    public void setExpire(long expire) {
        this.expire = expire;
    }

    public byte[] getProvider() {
        return provider;
    }

    public void setProvider(byte[] provider) {
        this.provider = provider;
    }

    private void buildTicket(byte[] rawData) {
        int counter = 0;
        int lastIndex = 0;

        for (int i = 0; i < rawData.length; i++) {
            if (rawData[i] == SEPARATOR) {
                if (counter < 9) {
                    if (counter == 0) {
                        ciphersuite = Arrays.copyOfRange(rawData, lastIndex, i);
                        System.out.println("ciphersuite: " + new String (ciphersuite));
                        lastIndex = i + 1;
                        counter++;
                    } else {
                        if (counter == 1) {
                            ks = Arrays.copyOfRange(rawData, lastIndex, i);
                            lastIndex = i + 1;
                            counter++;
                        } else {
                            if (counter == 2) {
                                kmAlgorithm = Arrays.copyOfRange(rawData, lastIndex, i);
                                System.out.println("kmAlg: " + new String (kmAlgorithm));
                                lastIndex = i + 1;
                                counter++;
                            } else {
                                if (counter == 3) {
                                    km = Arrays.copyOfRange(rawData, lastIndex, i);
                                    lastIndex = i + 1;
                                    counter++;
                                } else {
                                    if (counter == 4) {
                                        kaAlgorithm = Arrays.copyOfRange(rawData, lastIndex, i);
                                        lastIndex = i + 1;
                                        counter++;
                                    } else {
                                        if (counter == 5) {
                                            ka = Arrays.copyOfRange(rawData, lastIndex, i);
                                            lastIndex = i + 1;
                                            counter++;
                                        } else {
                                            if (counter == 6) {
                                                expire = Long.valueOf(new String(Arrays.copyOfRange(rawData, lastIndex, i)));
                                                lastIndex = i + 1;
                                                provider =Arrays.copyOfRange(rawData, lastIndex, rawData.length);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

