package com.cly.security.user;

import java.util.Properties;

import com.cly.security.password.PasswordEncrypt;
import com.cly.security.server.SecurityServerException;

public interface UserInfoService {
	
	public void initProperties(Properties p) throws SecurityServerException;
	
	public void setPasswordEncryptService(PasswordEncrypt pwdService);
	
	public UserInfo login(String jsonMsg) throws SecurityServerException;
	
}
