package com.cly.security.password;

import com.cly.security.server.SecurityServerException;

public interface PasswordEncrypt {

	public String encrypt (String pwd) throws SecurityServerException;
	
}
