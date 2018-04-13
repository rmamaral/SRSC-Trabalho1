package fct.srsc.stgc.phase2.model;

import java.net.InetAddress;
import java.util.Arrays;

public class AuthenticationRequest {

	private static final byte SEPARATOR = 0x00;

	private String username;
	private String nonce;
	private String ipmc;
	private byte[] authenticatorC;

	private InetAddress clientAddress;
	private int clientPort;

	public AuthenticationRequest() {
	}

	public AuthenticationRequest (byte [] rawData, InetAddress address, int port) {
		buildASRequest(rawData, address, port);
	}

	public AuthenticationRequest(String username, String nonce, String ipmc, byte[] authenticatorC, InetAddress clientAddress, int clientPort) {
		this.username = username;
		this.nonce = nonce;
		this.ipmc = ipmc;
		this.authenticatorC = authenticatorC;
		this.clientAddress = clientAddress;
		this.clientPort = clientPort;
	}

	public void setClientAddress(InetAddress clientAddress) {
		this.clientAddress = clientAddress;
	}

	public InetAddress getClientAddress() {
		return clientAddress;
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

	public int getClientPort() {
		return clientPort;
	}

	public void setClientPort(int clientPort) {
		this.clientPort = clientPort;
	}

	private void buildASRequest(byte[] data, InetAddress address, int port) {
		int lastIndex = 0;
		int counter = 0;

		this.setClientAddress(address);
		this.setClientPort(port);

		for (int i = 0; i < data.length; i++) {
			if (data[i] == SEPARATOR) {
				if (counter < 3) {
					if (counter == 0) {
						this.setUsername(new String(Arrays.copyOfRange(data, lastIndex, i)));
						lastIndex = i + 1;
						counter++;
					} else {
						if (counter == 1) {
							this.setNonce(new String(Arrays.copyOfRange(data, lastIndex, i)));
							lastIndex = i + 1;
							counter++;
						} else {
							if (counter == 2) {
								this.setIpmc(new String(Arrays.copyOfRange(data, lastIndex, i)));
								lastIndex = i + 1;
								this.setAuthenticatorC(Arrays.copyOfRange(data, lastIndex, data.length));
								break;
							}
						}
					}
				}
			}
		}
	}

}
