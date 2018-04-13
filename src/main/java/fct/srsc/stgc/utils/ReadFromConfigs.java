package fct.srsc.stgc.utils;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;

public class ReadFromConfigs {

	public static Key getKeyFromKeyStore(String type, String keystore, String key, char[] keyPassword, char[] keyStorePassword) {

		try {
			KeyStore keyStore = KeyStore.getInstance(type);
			// Keystore where symmetric keys are stored (type JCEKS)
			FileInputStream stream = new FileInputStream(keystore);
			keyStore.load(stream, keyStorePassword);

			Key key1 = keyStore.getKey(key, keyPassword);

			return key1;
		} catch (Exception e) {
			return null;
		}
	}
	
}
