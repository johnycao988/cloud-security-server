package com.cly.security.password;

import java.security.MessageDigest;
 

import com.cly.security.server.SecurityServerException;

import net.iharder.Base64; 
public class MD5EncryptService implements PasswordEncrypt {

	private static final String DT_MD5 = "MD5";

	@Override
	public String encrypt(String pwd) throws SecurityServerException {

		try {
			MessageDigest md5 = MessageDigest.getInstance(DT_MD5);
			md5.update(pwd.getBytes());
			byte[] bp = md5.digest();
			String vs = "{"+DT_MD5+"}"+Base64.encodeBytes(bp).toString(); 		 
		   
			return vs;
		} catch (Exception e) {
			e.printStackTrace();
			throw new SecurityServerException(e, null, e.getMessage());
		}
	}

}
