package com.cly.security.service.impl;

import java.security.MessageDigest;

import com.cly.security.PasswordEncrypt;
import com.cly.security.SecurityAuthException;

import net.iharder.Base64; 
public class MD5EncryptService implements PasswordEncrypt {

	private static final String DT_MD5 = "MD5";

	@Override
	public String encrypt(String pwd) throws SecurityAuthException {

		try {
			MessageDigest md5 = MessageDigest.getInstance(DT_MD5);
			md5.update(pwd.getBytes());
			byte[] bp = md5.digest();
			String vs = "{"+DT_MD5+"}"+Base64.encodeBytes(bp).toString(); 		 
		   
			return vs;
		} catch (Exception e) {
			throw new SecurityAuthException(e, null, e.getMessage());
		}
	}

}
