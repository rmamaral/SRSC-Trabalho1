package fct.srsc.authenticationServer;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class AuthenticationData {

	private List<byte[]> nounceList;
	
	public AuthenticationData() {
		this.nounceList = new ArrayList<byte[]>(); 
	}
	
	public List<byte[]> getNounceList(){
		return nounceList;
	}
	
	public boolean verifyUserAuth(String ipmc, String username) {
		try {
			Properties prop = new Properties();
			InputStream input = this.getClass().getResourceAsStream("/phase2/as/dacl.conf");
			
			prop.load(input);
			String[] splited = prop.getProperty(ipmc).split(";");
	
			for(int i = 0; i < splited.length; i++) {
				if(splited[i].equals(username)) {
					return true;
				}
			}
			return false;
		}
		catch(IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	public boolean verifyPwdHash(String username) {
		// TODO Auto-generated method stub
		return true;
	}
	
}
