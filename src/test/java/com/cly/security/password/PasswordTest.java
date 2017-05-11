package com.cly.security.password;

import org.junit.Test;

import com.cly.security.server.SecurityServerException;

import junit.framework.Assert;

public class PasswordTest {
	
	@Test
	public void testMD5() throws SecurityServerException {
		
		String pwd="ldap123";
		MD5EncryptService md5=new MD5EncryptService();
		
		pwd=md5.encrypt(pwd);
		
		Assert.assertEquals("{MD5}rdKIHN4TCYmfUBX6prz+6g==", pwd);
	}


}
