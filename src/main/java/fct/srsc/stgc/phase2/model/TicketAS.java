package fct.srsc.stgc.phase2.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class TicketAS {
	
	private byte[] ciphersuite;
	private byte[] ks;
	private byte[] kmAlgorithm;
	private byte[] km;
	private byte[] kaAlgorithm;
	private byte[] ka;
	private long expire;
	
	public TicketAS(){
		
	}

	public TicketAS(byte[] ciphersuite, byte[] ks, byte[] kmAlgorithm, byte[] km, byte[] kaAlgorithm, byte[] ka, long expire) {
		
		this.ciphersuite = ciphersuite;
		this.ks = ks;
		this.kmAlgorithm = kmAlgorithm;
		this.km = km;
		this.kaAlgorithm = kaAlgorithm;
		this.ka = ka;
		this.expire = expire;
	}

	public byte [] buildCore () throws IOException {
        ByteArrayOutputStream core = new ByteArrayOutputStream();
        core.write(ciphersuite);
        core.write(0x00);
        core.write(ks);
        core.write(0x00);
        core.write(kmAlgorithm);
        core.write(0x00);
        core.write(km);
        core.write(0x00);
        core.write(kaAlgorithm);
        core.write(0x00);
        core.write(ka);
        core.write(0x00);
        core.write(Long.toString(expire).getBytes());
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
	
	
}
