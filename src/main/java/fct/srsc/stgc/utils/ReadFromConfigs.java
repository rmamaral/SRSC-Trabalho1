package fct.srsc.stgc.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Properties;

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

	public static String readFromStgcSapAuth(String property) {
		try {
			Properties prop = new Properties();
			InputStream input = ReadFromConfigs.class.getClass().getResourceAsStream("/phase2/as/stgcsap.auth");

			// load a properties file
			prop.load(input);
			return prop.getProperty(property);

		} catch (IOException io) {
			io.printStackTrace();
			return null;
		}
	}

	public static String readKeyFromConfig(String username) {
		try {
			Properties prop = new Properties();
			InputStream input = ReadFromConfigs.class.getClass().getResourceAsStream("/phase2/as/users.conf");

			// load a properties file
			prop.load(input);
			return prop.getProperty(username);

		} catch (IOException io) {
			io.printStackTrace();
			return null;
		}
	}
	
}
